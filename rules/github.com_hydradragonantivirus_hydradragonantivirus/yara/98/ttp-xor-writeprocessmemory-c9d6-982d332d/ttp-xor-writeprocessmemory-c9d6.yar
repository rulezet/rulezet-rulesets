rule TTP_XOR_WriteProcessMemory_c9d6 {
  strings:
    $key_c9d6 = { 9e a4 [2] ac 86 [2] aa b3 [2] 84 b3 [2] bb af }

  condition:
    any of them
}