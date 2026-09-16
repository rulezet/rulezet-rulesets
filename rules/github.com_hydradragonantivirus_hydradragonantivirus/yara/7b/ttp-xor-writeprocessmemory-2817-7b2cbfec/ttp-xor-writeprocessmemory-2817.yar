rule TTP_XOR_WriteProcessMemory_2817 {
  strings:
    $key_2817 = { 7f 65 [2] 4d 47 [2] 4b 72 [2] 65 72 [2] 5a 6e }

  condition:
    any of them
}