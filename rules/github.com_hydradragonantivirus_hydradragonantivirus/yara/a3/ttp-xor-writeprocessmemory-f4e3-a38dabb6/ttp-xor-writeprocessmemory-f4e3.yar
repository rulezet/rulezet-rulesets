rule TTP_XOR_WriteProcessMemory_f4e3 {
  strings:
    $key_f4e3 = { a3 91 [2] 91 b3 [2] 97 86 [2] b9 86 [2] 86 9a }

  condition:
    any of them
}