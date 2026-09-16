rule TTP_XOR_WriteProcessMemory_f9f3 {
  strings:
    $key_f9f3 = { ae 81 [2] 9c a3 [2] 9a 96 [2] b4 96 [2] 8b 8a }

  condition:
    any of them
}