rule TTP_XOR_WriteProcessMemory_f955 {
  strings:
    $key_f955 = { ae 27 [2] 9c 05 [2] 9a 30 [2] b4 30 [2] 8b 2c }

  condition:
    any of them
}