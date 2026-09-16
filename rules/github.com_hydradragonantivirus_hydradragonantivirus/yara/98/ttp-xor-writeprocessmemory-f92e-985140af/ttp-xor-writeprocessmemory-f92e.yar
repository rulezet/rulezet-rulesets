rule TTP_XOR_WriteProcessMemory_f92e {
  strings:
    $key_f92e = { ae 5c [2] 9c 7e [2] 9a 4b [2] b4 4b [2] 8b 57 }

  condition:
    any of them
}