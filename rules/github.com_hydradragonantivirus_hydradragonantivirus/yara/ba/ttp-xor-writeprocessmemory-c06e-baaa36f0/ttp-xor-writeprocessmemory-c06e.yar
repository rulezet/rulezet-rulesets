rule TTP_XOR_WriteProcessMemory_c06e {
  strings:
    $key_c06e = { 97 1c [2] a5 3e [2] a3 0b [2] 8d 0b [2] b2 17 }

  condition:
    any of them
}