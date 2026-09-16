rule TTP_XOR_WriteProcessMemory_0427 {
  strings:
    $key_0427 = { 53 55 [2] 61 77 [2] 67 42 [2] 49 42 [2] 76 5e }

  condition:
    any of them
}