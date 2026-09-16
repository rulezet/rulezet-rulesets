rule TTP_XOR_WriteProcessMemory_4a17 {
  strings:
    $key_4a17 = { 1d 65 [2] 2f 47 [2] 29 72 [2] 07 72 [2] 38 6e }

  condition:
    any of them
}