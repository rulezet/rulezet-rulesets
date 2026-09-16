rule TTP_XOR_WriteProcessMemory_f4e4 {
  strings:
    $key_f4e4 = { a3 96 [2] 91 b4 [2] 97 81 [2] b9 81 [2] 86 9d }

  condition:
    any of them
}