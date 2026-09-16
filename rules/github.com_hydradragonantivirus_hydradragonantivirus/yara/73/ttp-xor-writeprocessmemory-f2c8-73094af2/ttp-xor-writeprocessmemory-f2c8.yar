rule TTP_XOR_WriteProcessMemory_f2c8 {
  strings:
    $key_f2c8 = { a5 ba [2] 97 98 [2] 91 ad [2] bf ad [2] 80 b1 }

  condition:
    any of them
}