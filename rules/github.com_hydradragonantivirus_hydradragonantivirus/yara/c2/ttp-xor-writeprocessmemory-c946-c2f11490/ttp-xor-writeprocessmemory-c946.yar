rule TTP_XOR_WriteProcessMemory_c946 {
  strings:
    $key_c946 = { 9e 34 [2] ac 16 [2] aa 23 [2] 84 23 [2] bb 3f }

  condition:
    any of them
}