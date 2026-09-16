rule TTP_XOR_WriteProcessMemory_f460 {
  strings:
    $key_f460 = { a3 12 [2] 91 30 [2] 97 05 [2] b9 05 [2] 86 19 }

  condition:
    any of them
}