rule TTP_XOR_WriteProcessMemory_a0fe {
  strings:
    $key_a0fe = { f7 8c [2] c5 ae [2] c3 9b [2] ed 9b [2] d2 87 }

  condition:
    any of them
}