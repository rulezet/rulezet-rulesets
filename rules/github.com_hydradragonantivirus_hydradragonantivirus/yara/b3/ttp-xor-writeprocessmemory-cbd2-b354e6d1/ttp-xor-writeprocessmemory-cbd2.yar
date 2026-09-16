rule TTP_XOR_WriteProcessMemory_cbd2 {
  strings:
    $key_cbd2 = { 9c a0 [2] ae 82 [2] a8 b7 [2] 86 b7 [2] b9 ab }

  condition:
    any of them
}