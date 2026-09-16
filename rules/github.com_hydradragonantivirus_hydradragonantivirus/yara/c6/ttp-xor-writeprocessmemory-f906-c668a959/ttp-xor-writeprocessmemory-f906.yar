rule TTP_XOR_WriteProcessMemory_f906 {
  strings:
    $key_f906 = { ae 74 [2] 9c 56 [2] 9a 63 [2] b4 63 [2] 8b 7f }

  condition:
    any of them
}