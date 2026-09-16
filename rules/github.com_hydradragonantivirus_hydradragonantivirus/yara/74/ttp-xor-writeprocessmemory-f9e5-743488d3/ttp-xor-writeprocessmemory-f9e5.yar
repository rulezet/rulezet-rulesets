rule TTP_XOR_WriteProcessMemory_f9e5 {
  strings:
    $key_f9e5 = { ae 97 [2] 9c b5 [2] 9a 80 [2] b4 80 [2] 8b 9c }

  condition:
    any of them
}