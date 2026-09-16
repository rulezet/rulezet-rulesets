rule TTP_XOR_WriteProcessMemory_c2fe {
  strings:
    $key_c2fe = { 95 8c [2] a7 ae [2] a1 9b [2] 8f 9b [2] b0 87 }

  condition:
    any of them
}