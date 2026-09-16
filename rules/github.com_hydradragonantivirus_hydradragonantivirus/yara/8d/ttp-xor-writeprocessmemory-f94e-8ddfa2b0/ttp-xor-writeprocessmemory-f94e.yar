rule TTP_XOR_WriteProcessMemory_f94e {
  strings:
    $key_f94e = { ae 3c [2] 9c 1e [2] 9a 2b [2] b4 2b [2] 8b 37 }

  condition:
    any of them
}