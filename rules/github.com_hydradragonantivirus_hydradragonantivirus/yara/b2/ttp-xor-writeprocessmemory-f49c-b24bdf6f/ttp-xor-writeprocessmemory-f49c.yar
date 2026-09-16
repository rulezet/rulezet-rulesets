rule TTP_XOR_WriteProcessMemory_f49c {
  strings:
    $key_f49c = { a3 ee [2] 91 cc [2] 97 f9 [2] b9 f9 [2] 86 e5 }

  condition:
    any of them
}