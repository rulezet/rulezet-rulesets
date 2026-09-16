rule TTP_XOR_WriteProcessMemory_6963 {
  strings:
    $key_6963 = { 3e 11 [2] 0c 33 [2] 0a 06 [2] 24 06 [2] 1b 1a }

  condition:
    any of them
}