rule TTP_XOR_WriteProcessMemory_7e74 {
  strings:
    $key_7e74 = { 29 06 [2] 1b 24 [2] 1d 11 [2] 33 11 [2] 0c 0d }

  condition:
    any of them
}