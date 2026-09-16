rule TTP_XOR_WriteProcessMemory_52d0 {
  strings:
    $key_52d0 = { 05 a2 [2] 37 80 [2] 31 b5 [2] 1f b5 [2] 20 a9 }

  condition:
    any of them
}