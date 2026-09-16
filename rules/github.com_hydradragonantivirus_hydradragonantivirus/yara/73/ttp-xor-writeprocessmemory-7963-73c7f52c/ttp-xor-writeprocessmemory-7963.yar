rule TTP_XOR_WriteProcessMemory_7963 {
  strings:
    $key_7963 = { 2e 11 [2] 1c 33 [2] 1a 06 [2] 34 06 [2] 0b 1a }

  condition:
    any of them
}