rule TTP_XOR_WriteProcessMemory_f473 {
  strings:
    $key_f473 = { a3 01 [2] 91 23 [2] 97 16 [2] b9 16 [2] 86 0a }

  condition:
    any of them
}