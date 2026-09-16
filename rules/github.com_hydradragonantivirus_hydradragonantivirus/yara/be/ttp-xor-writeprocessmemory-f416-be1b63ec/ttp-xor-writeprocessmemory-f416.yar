rule TTP_XOR_WriteProcessMemory_f416 {
  strings:
    $key_f416 = { a3 64 [2] 91 46 [2] 97 73 [2] b9 73 [2] 86 6f }

  condition:
    any of them
}