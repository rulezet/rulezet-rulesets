rule TTP_XOR_WriteProcessMemory_f9eb {
  strings:
    $key_f9eb = { ae 99 [2] 9c bb [2] 9a 8e [2] b4 8e [2] 8b 92 }

  condition:
    any of them
}