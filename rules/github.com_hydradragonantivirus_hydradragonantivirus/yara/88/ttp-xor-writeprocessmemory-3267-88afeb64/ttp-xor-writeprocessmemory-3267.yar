rule TTP_XOR_WriteProcessMemory_3267 {
  strings:
    $key_3267 = { 65 15 [2] 57 37 [2] 51 02 [2] 7f 02 [2] 40 1e }

  condition:
    any of them
}