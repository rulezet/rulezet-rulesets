rule TTP_XOR_WriteProcessMemory_d76e {
  strings:
    $key_d76e = { 80 1c [2] b2 3e [2] b4 0b [2] 9a 0b [2] a5 17 }

  condition:
    any of them
}