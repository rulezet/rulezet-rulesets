rule TTP_XOR_WriteProcessMemory_f216 {
  strings:
    $key_f216 = { a5 64 [2] 97 46 [2] 91 73 [2] bf 73 [2] 80 6f }

  condition:
    any of them
}