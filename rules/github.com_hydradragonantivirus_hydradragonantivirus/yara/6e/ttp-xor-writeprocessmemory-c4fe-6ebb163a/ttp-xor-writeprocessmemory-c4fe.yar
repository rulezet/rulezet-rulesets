rule TTP_XOR_WriteProcessMemory_c4fe {
  strings:
    $key_c4fe = { 93 8c [2] a1 ae [2] a7 9b [2] 89 9b [2] b6 87 }

  condition:
    any of them
}