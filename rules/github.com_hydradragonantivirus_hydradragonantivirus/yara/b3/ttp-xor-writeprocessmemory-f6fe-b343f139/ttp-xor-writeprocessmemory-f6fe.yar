rule TTP_XOR_WriteProcessMemory_f6fe {
  strings:
    $key_f6fe = { a1 8c [2] 93 ae [2] 95 9b [2] bb 9b [2] 84 87 }

  condition:
    any of them
}