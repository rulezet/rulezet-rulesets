rule TTP_XOR_WriteProcessMemory_f2da {
  strings:
    $key_f2da = { a5 a8 [2] 97 8a [2] 91 bf [2] bf bf [2] 80 a3 }

  condition:
    any of them
}