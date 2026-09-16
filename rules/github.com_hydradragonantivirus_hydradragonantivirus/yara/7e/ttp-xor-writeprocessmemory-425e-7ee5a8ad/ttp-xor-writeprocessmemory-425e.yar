rule TTP_XOR_WriteProcessMemory_425e {
  strings:
    $key_425e = { 15 2c [2] 27 0e [2] 21 3b [2] 0f 3b [2] 30 27 }

  condition:
    any of them
}