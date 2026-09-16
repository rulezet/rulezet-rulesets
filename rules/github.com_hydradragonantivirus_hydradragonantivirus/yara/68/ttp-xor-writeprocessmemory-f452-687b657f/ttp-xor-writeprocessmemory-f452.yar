rule TTP_XOR_WriteProcessMemory_f452 {
  strings:
    $key_f452 = { a3 20 [2] 91 02 [2] 97 37 [2] b9 37 [2] 86 2b }

  condition:
    any of them
}