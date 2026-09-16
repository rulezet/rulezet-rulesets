rule TTP_XOR_WriteProcessMemory_3027 {
  strings:
    $key_3027 = { 67 55 [2] 55 77 [2] 53 42 [2] 7d 42 [2] 42 5e }

  condition:
    any of them
}