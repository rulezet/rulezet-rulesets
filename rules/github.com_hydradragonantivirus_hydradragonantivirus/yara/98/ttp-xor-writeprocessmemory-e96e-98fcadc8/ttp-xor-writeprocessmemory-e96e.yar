rule TTP_XOR_WriteProcessMemory_e96e {
  strings:
    $key_e96e = { be 1c [2] 8c 3e [2] 8a 0b [2] a4 0b [2] 9b 17 }

  condition:
    any of them
}