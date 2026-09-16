rule TTP_XOR_WriteProcessMemory_385e {
  strings:
    $key_385e = { 6f 2c [2] 5d 0e [2] 5b 3b [2] 75 3b [2] 4a 27 }

  condition:
    any of them
}