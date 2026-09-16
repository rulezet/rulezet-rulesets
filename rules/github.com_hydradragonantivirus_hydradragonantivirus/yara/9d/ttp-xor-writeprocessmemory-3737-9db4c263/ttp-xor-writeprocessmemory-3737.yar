rule TTP_XOR_WriteProcessMemory_3737 {
  strings:
    $key_3737 = { 60 45 [2] 52 67 [2] 54 52 [2] 7a 52 [2] 45 4e }

  condition:
    any of them
}