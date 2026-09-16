rule TTP_XOR_WriteProcessMemory_7e17 {
  strings:
    $key_7e17 = { 29 65 [2] 1b 47 [2] 1d 72 [2] 33 72 [2] 0c 6e }

  condition:
    any of them
}