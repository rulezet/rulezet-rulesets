rule TTP_XOR_WriteProcessMemory_d5fe {
  strings:
    $key_d5fe = { 82 8c [2] b0 ae [2] b6 9b [2] 98 9b [2] a7 87 }

  condition:
    any of them
}