rule TTP_XOR_WriteProcessMemory_c3fe {
  strings:
    $key_c3fe = { 94 8c [2] a6 ae [2] a0 9b [2] 8e 9b [2] b1 87 }

  condition:
    any of them
}