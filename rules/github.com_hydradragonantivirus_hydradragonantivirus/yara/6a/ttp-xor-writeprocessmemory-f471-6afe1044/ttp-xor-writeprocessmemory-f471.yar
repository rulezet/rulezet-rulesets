rule TTP_XOR_WriteProcessMemory_f471 {
  strings:
    $key_f471 = { a3 03 [2] 91 21 [2] 97 14 [2] b9 14 [2] 86 08 }

  condition:
    any of them
}