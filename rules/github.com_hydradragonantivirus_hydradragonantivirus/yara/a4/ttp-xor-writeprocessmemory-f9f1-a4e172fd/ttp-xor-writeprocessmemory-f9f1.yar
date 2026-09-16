rule TTP_XOR_WriteProcessMemory_f9f1 {
  strings:
    $key_f9f1 = { ae 83 [2] 9c a1 [2] 9a 94 [2] b4 94 [2] 8b 88 }

  condition:
    any of them
}