rule TTP_XOR_WriteProcessMemory_7e62 {
  strings:
    $key_7e62 = { 29 10 [2] 1b 32 [2] 1d 07 [2] 33 07 [2] 0c 1b }

  condition:
    any of them
}