rule TTP_XOR_WriteProcessMemory_6e07 {
  strings:
    $key_6e07 = { 39 75 [2] 0b 57 [2] 0d 62 [2] 23 62 [2] 1c 7e }

  condition:
    any of them
}