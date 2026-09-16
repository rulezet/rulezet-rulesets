rule TTP_XOR_WriteProcessMemory_f900 {
  strings:
    $key_f900 = { ae 72 [2] 9c 50 [2] 9a 65 [2] b4 65 [2] 8b 79 }

  condition:
    any of them
}