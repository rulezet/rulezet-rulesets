rule TTP_XOR_WriteProcessMemory_3b21 {
  strings:
    $key_3b21 = { 6c 53 [2] 5e 71 [2] 58 44 [2] 76 44 [2] 49 58 }

  condition:
    any of them
}