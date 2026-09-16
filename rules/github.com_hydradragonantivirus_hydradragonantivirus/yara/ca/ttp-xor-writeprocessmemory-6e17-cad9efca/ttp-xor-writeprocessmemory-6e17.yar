rule TTP_XOR_WriteProcessMemory_6e17 {
  strings:
    $key_6e17 = { 39 65 [2] 0b 47 [2] 0d 72 [2] 23 72 [2] 1c 6e }

  condition:
    any of them
}