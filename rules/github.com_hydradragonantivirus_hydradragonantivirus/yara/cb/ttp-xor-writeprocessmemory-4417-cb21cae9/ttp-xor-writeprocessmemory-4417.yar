rule TTP_XOR_WriteProcessMemory_4417 {
  strings:
    $key_4417 = { 13 65 [2] 21 47 [2] 27 72 [2] 09 72 [2] 36 6e }

  condition:
    any of them
}