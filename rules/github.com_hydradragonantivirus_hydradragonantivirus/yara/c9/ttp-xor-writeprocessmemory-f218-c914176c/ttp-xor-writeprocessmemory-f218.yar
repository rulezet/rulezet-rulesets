rule TTP_XOR_WriteProcessMemory_f218 {
  strings:
    $key_f218 = { a5 6a [2] 97 48 [2] 91 7d [2] bf 7d [2] 80 61 }

  condition:
    any of them
}