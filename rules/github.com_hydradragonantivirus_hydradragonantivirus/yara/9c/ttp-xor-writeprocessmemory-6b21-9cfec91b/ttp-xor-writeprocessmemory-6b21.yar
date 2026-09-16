rule TTP_XOR_WriteProcessMemory_6b21 {
  strings:
    $key_6b21 = { 3c 53 [2] 0e 71 [2] 08 44 [2] 26 44 [2] 19 58 }

  condition:
    any of them
}