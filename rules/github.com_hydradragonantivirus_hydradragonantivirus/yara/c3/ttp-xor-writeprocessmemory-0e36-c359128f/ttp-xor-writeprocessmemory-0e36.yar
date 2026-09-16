rule TTP_XOR_WriteProcessMemory_0e36 {
  strings:
    $key_0e36 = { 59 44 [2] 6b 66 [2] 6d 53 [2] 43 53 [2] 7c 4f }

  condition:
    any of them
}