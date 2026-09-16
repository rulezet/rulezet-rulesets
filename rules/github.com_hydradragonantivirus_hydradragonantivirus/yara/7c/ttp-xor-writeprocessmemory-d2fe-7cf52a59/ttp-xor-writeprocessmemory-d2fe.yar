rule TTP_XOR_WriteProcessMemory_d2fe {
  strings:
    $key_d2fe = { 85 8c [2] b7 ae [2] b1 9b [2] 9f 9b [2] a0 87 }

  condition:
    any of them
}