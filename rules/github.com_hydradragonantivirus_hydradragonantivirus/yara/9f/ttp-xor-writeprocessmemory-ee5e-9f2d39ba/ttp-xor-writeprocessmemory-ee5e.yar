rule TTP_XOR_WriteProcessMemory_ee5e {
  strings:
    $key_ee5e = { b9 2c [2] 8b 0e [2] 8d 3b [2] a3 3b [2] 9c 27 }

  condition:
    any of them
}