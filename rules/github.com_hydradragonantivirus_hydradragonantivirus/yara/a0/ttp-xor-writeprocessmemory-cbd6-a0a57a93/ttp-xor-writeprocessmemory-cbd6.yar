rule TTP_XOR_WriteProcessMemory_cbd6 {
  strings:
    $key_cbd6 = { 9c a4 [2] ae 86 [2] a8 b3 [2] 86 b3 [2] b9 af }

  condition:
    any of them
}