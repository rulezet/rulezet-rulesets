rule TTP_XOR_WriteProcessMemory_f92b {
  strings:
    $key_f92b = { ae 59 [2] 9c 7b [2] 9a 4e [2] b4 4e [2] 8b 52 }

  condition:
    any of them
}