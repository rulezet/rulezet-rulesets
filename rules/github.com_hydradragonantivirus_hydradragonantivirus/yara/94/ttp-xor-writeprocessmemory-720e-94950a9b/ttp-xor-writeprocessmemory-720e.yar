rule TTP_XOR_WriteProcessMemory_720e {
  strings:
    $key_720e = { 25 7c [2] 17 5e [2] 11 6b [2] 3f 6b [2] 00 77 }

  condition:
    any of them
}