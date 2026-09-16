rule TTP_XOR_WriteProcessMemory_f2df {
  strings:
    $key_f2df = { a5 ad [2] 97 8f [2] 91 ba [2] bf ba [2] 80 a6 }

  condition:
    any of them
}