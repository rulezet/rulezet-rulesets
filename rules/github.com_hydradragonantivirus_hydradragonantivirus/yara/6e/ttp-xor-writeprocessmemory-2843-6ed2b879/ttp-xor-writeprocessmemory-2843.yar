rule TTP_XOR_WriteProcessMemory_2843 {
  strings:
    $key_2843 = { 7f 31 [2] 4d 13 [2] 4b 26 [2] 65 26 [2] 5a 3a }

  condition:
    any of them
}