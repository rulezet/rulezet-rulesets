rule TTP_XOR_WriteProcessMemory_b0fe {
  strings:
    $key_b0fe = { e7 8c [2] d5 ae [2] d3 9b [2] fd 9b [2] c2 87 }

  condition:
    any of them
}