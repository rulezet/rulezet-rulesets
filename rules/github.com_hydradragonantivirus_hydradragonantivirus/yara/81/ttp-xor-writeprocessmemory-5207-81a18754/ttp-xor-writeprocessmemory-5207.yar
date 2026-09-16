rule TTP_XOR_WriteProcessMemory_5207 {
  strings:
    $key_5207 = { 05 75 [2] 37 57 [2] 31 62 [2] 1f 62 [2] 20 7e }

  condition:
    any of them
}