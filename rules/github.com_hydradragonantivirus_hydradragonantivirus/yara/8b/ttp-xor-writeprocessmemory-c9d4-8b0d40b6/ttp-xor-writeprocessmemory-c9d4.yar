rule TTP_XOR_WriteProcessMemory_c9d4 {
  strings:
    $key_c9d4 = { 9e a6 [2] ac 84 [2] aa b1 [2] 84 b1 [2] bb ad }

  condition:
    any of them
}