rule TTP_XOR_WriteProcessMemory_4267 {
  strings:
    $key_4267 = { 15 15 [2] 27 37 [2] 21 02 [2] 0f 02 [2] 30 1e }

  condition:
    any of them
}