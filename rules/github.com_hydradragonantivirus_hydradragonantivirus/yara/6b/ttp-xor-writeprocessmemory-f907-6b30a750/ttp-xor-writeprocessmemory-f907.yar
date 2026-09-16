rule TTP_XOR_WriteProcessMemory_f907 {
  strings:
    $key_f907 = { ae 75 [2] 9c 57 [2] 9a 62 [2] b4 62 [2] 8b 7e }

  condition:
    any of them
}