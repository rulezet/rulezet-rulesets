rule TTP_XOR_WriteProcessMemory_7180 {
  strings:
    $key_7180 = { 26 f2 [2] 14 d0 [2] 12 e5 [2] 3c e5 [2] 03 f9 }

  condition:
    any of them
}