rule TTP_XOR_WriteProcessMemory_d16e {
  strings:
    $key_d16e = { 86 1c [2] b4 3e [2] b2 0b [2] 9c 0b [2] a3 17 }

  condition:
    any of them
}