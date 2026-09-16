rule TTP_XOR_WriteProcessMemory_f967 {
  strings:
    $key_f967 = { ae 15 [2] 9c 37 [2] 9a 02 [2] b4 02 [2] 8b 1e }

  condition:
    any of them
}