rule TTP_XOR_WriteProcessMemory_a2fe {
  strings:
    $key_a2fe = { f5 8c [2] c7 ae [2] c1 9b [2] ef 9b [2] d0 87 }

  condition:
    any of them
}