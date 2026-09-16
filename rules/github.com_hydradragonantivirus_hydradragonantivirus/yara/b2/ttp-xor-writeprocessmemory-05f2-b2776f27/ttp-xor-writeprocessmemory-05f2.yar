rule TTP_XOR_WriteProcessMemory_05f2 {
  strings:
    $key_05f2 = { 52 80 [2] 60 a2 [2] 66 97 [2] 48 97 [2] 77 8b }

  condition:
    any of them
}