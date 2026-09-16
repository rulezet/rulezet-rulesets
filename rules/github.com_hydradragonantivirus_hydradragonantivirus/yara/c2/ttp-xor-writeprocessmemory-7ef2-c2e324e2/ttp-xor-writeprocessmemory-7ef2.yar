rule TTP_XOR_WriteProcessMemory_7ef2 {
  strings:
    $key_7ef2 = { 29 80 [2] 1b a2 [2] 1d 97 [2] 33 97 [2] 0c 8b }

  condition:
    any of them
}