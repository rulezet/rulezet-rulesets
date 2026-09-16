rule TTP_XOR_WriteProcessMemory_c9d2 {
  strings:
    $key_c9d2 = { 9e a0 [2] ac 82 [2] aa b7 [2] 84 b7 [2] bb ab }

  condition:
    any of them
}