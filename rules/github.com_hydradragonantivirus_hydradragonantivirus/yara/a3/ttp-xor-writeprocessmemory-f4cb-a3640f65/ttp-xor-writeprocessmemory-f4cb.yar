rule TTP_XOR_WriteProcessMemory_f4cb {
  strings:
    $key_f4cb = { a3 b9 [2] 91 9b [2] 97 ae [2] b9 ae [2] 86 b2 }

  condition:
    any of them
}