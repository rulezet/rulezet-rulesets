rule TTP_XOR_WriteProcessMemory_157c {
  strings:
    $key_157c = { 42 0e [2] 70 2c [2] 76 19 [2] 58 19 [2] 67 05 }

  condition:
    any of them
}