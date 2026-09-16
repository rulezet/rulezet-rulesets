rule TTP_XOR_WriteProcessMemory_2027 {
  strings:
    $key_2027 = { 77 55 [2] 45 77 [2] 43 42 [2] 6d 42 [2] 52 5e }

  condition:
    any of them
}