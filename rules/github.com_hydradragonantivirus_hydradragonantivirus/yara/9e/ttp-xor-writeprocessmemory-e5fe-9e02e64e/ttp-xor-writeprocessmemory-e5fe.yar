rule TTP_XOR_WriteProcessMemory_e5fe {
  strings:
    $key_e5fe = { b2 8c [2] 80 ae [2] 86 9b [2] a8 9b [2] 97 87 }

  condition:
    any of them
}