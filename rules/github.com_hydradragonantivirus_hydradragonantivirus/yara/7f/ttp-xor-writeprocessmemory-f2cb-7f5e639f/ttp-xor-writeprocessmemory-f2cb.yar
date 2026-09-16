rule TTP_XOR_WriteProcessMemory_f2cb {
  strings:
    $key_f2cb = { a5 b9 [2] 97 9b [2] 91 ae [2] bf ae [2] 80 b2 }

  condition:
    any of them
}