rule TTP_XOR_WriteProcessMemory_f462 {
  strings:
    $key_f462 = { a3 10 [2] 91 32 [2] 97 07 [2] b9 07 [2] 86 1b }

  condition:
    any of them
}