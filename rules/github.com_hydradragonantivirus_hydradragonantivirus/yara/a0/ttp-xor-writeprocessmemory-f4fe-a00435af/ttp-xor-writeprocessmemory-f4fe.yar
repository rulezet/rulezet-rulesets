rule TTP_XOR_WriteProcessMemory_f4fe {
  strings:
    $key_f4fe = { a3 8c [2] 91 ae [2] 97 9b [2] b9 9b [2] 86 87 }

  condition:
    any of them
}