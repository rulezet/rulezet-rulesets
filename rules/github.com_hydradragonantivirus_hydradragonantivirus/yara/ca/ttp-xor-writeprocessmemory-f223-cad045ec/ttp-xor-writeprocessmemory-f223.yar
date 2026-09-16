rule TTP_XOR_WriteProcessMemory_f223 {
  strings:
    $key_f223 = { a5 51 [2] 97 73 [2] 91 46 [2] bf 46 [2] 80 5a }

  condition:
    any of them
}