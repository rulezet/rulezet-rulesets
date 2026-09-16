rule TTP_XOR_WriteProcessMemory_f1cb {
  strings:
    $key_f1cb = { a6 b9 [2] 94 9b [2] 92 ae [2] bc ae [2] 83 b2 }

  condition:
    any of them
}