rule TTP_XOR_WriteProcessMemory_b3fe {
  strings:
    $key_b3fe = { e4 8c [2] d6 ae [2] d0 9b [2] fe 9b [2] c1 87 }

  condition:
    any of them
}