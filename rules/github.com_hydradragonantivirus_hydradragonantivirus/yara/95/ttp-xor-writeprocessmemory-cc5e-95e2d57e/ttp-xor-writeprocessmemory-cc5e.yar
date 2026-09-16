rule TTP_XOR_WriteProcessMemory_cc5e {
  strings:
    $key_cc5e = { 9b 2c [2] a9 0e [2] af 3b [2] 81 3b [2] be 27 }

  condition:
    any of them
}