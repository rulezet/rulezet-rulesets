rule TTP_XOR_WriteProcessMemory_2e36 {
  strings:
    $key_2e36 = { 79 44 [2] 4b 66 [2] 4d 53 [2] 63 53 [2] 5c 4f }

  condition:
    any of them
}