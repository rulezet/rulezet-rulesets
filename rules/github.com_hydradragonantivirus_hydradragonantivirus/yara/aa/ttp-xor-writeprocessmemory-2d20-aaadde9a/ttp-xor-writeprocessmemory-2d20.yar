rule TTP_XOR_WriteProcessMemory_2d20 {
  strings:
    $key_2d20 = { 7a 52 [2] 48 70 [2] 4e 45 [2] 60 45 [2] 5f 59 }

  condition:
    any of them
}