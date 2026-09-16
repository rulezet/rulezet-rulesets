rule TTP_XOR_WriteProcessMemory_cbd1 {
  strings:
    $key_cbd1 = { 9c a3 [2] ae 81 [2] a8 b4 [2] 86 b4 [2] b9 a8 }

  condition:
    any of them
}