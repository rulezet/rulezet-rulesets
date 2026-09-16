rule TTP_XOR_WriteProcessMemory_f786 {
  strings:
    $key_f786 = { a0 f4 [2] 92 d6 [2] 94 e3 [2] ba e3 [2] 85 ff }

  condition:
    any of them
}