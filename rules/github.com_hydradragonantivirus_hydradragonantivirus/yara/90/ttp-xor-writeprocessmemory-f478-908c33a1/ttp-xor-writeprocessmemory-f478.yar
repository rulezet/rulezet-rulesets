rule TTP_XOR_WriteProcessMemory_f478 {
  strings:
    $key_f478 = { a3 0a [2] 91 28 [2] 97 1d [2] b9 1d [2] 86 01 }

  condition:
    any of them
}