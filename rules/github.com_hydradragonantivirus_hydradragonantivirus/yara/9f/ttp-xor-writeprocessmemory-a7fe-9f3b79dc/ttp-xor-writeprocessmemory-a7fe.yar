rule TTP_XOR_WriteProcessMemory_a7fe {
  strings:
    $key_a7fe = { f0 8c [2] c2 ae [2] c4 9b [2] ea 9b [2] d5 87 }

  condition:
    any of them
}