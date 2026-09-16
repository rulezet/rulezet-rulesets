rule TTP_XOR_WriteProcessMemory_d17e {
  strings:
    $key_d17e = { 86 0c [2] b4 2e [2] b2 1b [2] 9c 1b [2] a3 07 }

  condition:
    any of them
}