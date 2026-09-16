rule TTP_XOR_WriteProcessMemory_2e22 {
  strings:
    $key_2e22 = { 79 50 [2] 4b 72 [2] 4d 47 [2] 63 47 [2] 5c 5b }

  condition:
    any of them
}