rule TTP_XOR_WriteProcessMemory_f9f2 {
  strings:
    $key_f9f2 = { ae 80 [2] 9c a2 [2] 9a 97 [2] b4 97 [2] 8b 8b }

  condition:
    any of them
}