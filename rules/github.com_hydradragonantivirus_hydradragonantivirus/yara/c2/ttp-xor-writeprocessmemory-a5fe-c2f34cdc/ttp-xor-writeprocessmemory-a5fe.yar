rule TTP_XOR_WriteProcessMemory_a5fe {
  strings:
    $key_a5fe = { f2 8c [2] c0 ae [2] c6 9b [2] e8 9b [2] d7 87 }

  condition:
    any of them
}