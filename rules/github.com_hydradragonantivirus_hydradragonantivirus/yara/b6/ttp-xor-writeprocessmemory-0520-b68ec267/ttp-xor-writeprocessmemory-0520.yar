rule TTP_XOR_WriteProcessMemory_0520 {
  strings:
    $key_0520 = { 52 52 [2] 60 70 [2] 66 45 [2] 48 45 [2] 77 59 }

  condition:
    any of them
}