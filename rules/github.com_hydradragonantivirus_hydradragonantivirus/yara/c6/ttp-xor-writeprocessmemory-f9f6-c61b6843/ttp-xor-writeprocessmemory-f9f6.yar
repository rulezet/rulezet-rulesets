rule TTP_XOR_WriteProcessMemory_f9f6 {
  strings:
    $key_f9f6 = { ae 84 [2] 9c a6 [2] 9a 93 [2] b4 93 [2] 8b 8f }

  condition:
    any of them
}