rule TTP_XOR_WriteProcessMemory_f96c {
  strings:
    $key_f96c = { ae 1e [2] 9c 3c [2] 9a 09 [2] b4 09 [2] 8b 15 }

  condition:
    any of them
}