rule TTP_XOR_WriteProcessMemory_f4c5 {
  strings:
    $key_f4c5 = { a3 b7 [2] 91 95 [2] 97 a0 [2] b9 a0 [2] 86 bc }

  condition:
    any of them
}