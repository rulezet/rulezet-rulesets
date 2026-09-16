rule TTP_XOR_WriteProcessMemory_3013 {
  strings:
    $key_3013 = { 67 61 [2] 55 43 [2] 53 76 [2] 7d 76 [2] 42 6a }

  condition:
    any of them
}