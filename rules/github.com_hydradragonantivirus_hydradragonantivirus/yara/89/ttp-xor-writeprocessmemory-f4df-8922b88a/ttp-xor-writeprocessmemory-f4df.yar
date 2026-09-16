rule TTP_XOR_WriteProcessMemory_f4df {
  strings:
    $key_f4df = { a3 ad [2] 91 8f [2] 97 ba [2] b9 ba [2] 86 a6 }

  condition:
    any of them
}