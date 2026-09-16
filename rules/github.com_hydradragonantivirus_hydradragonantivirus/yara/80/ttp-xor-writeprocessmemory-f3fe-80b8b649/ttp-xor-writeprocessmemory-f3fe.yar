rule TTP_XOR_WriteProcessMemory_f3fe {
  strings:
    $key_f3fe = { a4 8c [2] 96 ae [2] 90 9b [2] be 9b [2] 81 87 }

  condition:
    any of them
}