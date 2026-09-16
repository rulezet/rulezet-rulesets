rule TTP_XOR_WriteProcessMemory_f930 {
  strings:
    $key_f930 = { ae 42 [2] 9c 60 [2] 9a 55 [2] b4 55 [2] 8b 49 }

  condition:
    any of them
}