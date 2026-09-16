rule TTP_XOR_WriteProcessMemory_f4a6 {
  strings:
    $key_f4a6 = { a3 d4 [2] 91 f6 [2] 97 c3 [2] b9 c3 [2] 86 df }

  condition:
    any of them
}