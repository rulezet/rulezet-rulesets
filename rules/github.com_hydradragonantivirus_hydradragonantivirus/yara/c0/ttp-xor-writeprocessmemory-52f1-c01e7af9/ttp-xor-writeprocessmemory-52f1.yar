rule TTP_XOR_WriteProcessMemory_52f1 {
  strings:
    $key_52f1 = { 05 83 [2] 37 a1 [2] 31 94 [2] 1f 94 [2] 20 88 }

  condition:
    any of them
}