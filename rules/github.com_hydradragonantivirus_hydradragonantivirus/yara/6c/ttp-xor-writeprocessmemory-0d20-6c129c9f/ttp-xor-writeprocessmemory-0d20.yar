rule TTP_XOR_WriteProcessMemory_0d20 {
  strings:
    $key_0d20 = { 5a 52 [2] 68 70 [2] 6e 45 [2] 40 45 [2] 7f 59 }

  condition:
    any of them
}