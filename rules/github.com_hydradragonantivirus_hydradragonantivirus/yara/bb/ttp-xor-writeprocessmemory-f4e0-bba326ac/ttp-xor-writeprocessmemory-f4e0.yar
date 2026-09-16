rule TTP_XOR_WriteProcessMemory_f4e0 {
  strings:
    $key_f4e0 = { a3 92 [2] 91 b0 [2] 97 85 [2] b9 85 [2] 86 99 }

  condition:
    any of them
}