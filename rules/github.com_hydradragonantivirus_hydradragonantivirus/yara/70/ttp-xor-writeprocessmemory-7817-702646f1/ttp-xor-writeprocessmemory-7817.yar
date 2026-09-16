rule TTP_XOR_WriteProcessMemory_7817 {
  strings:
    $key_7817 = { 2f 65 [2] 1d 47 [2] 1b 72 [2] 35 72 [2] 0a 6e }

  condition:
    any of them
}