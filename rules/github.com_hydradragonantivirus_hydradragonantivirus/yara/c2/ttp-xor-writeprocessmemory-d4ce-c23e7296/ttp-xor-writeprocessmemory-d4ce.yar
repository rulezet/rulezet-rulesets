rule TTP_XOR_WriteProcessMemory_d4ce {
  strings:
    $key_d4ce = { 83 bc [2] b1 9e [2] b7 ab [2] 99 ab [2] a6 b7 }

  condition:
    any of them
}