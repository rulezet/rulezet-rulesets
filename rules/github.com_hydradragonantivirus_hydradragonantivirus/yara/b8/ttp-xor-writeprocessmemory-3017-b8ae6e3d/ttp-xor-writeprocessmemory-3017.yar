rule TTP_XOR_WriteProcessMemory_3017 {
  strings:
    $key_3017 = { 67 65 [2] 55 47 [2] 53 72 [2] 7d 72 [2] 42 6e }

  condition:
    any of them
}