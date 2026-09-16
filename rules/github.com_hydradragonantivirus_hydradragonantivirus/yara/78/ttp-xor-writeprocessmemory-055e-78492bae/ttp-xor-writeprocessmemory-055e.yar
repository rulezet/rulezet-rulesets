rule TTP_XOR_WriteProcessMemory_055e {
  strings:
    $key_055e = { 52 2c [2] 60 0e [2] 66 3b [2] 48 3b [2] 77 27 }

  condition:
    any of them
}