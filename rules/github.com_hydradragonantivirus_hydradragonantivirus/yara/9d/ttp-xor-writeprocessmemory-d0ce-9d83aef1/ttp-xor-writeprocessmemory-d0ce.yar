rule TTP_XOR_WriteProcessMemory_d0ce {
  strings:
    $key_d0ce = { 87 bc [2] b5 9e [2] b3 ab [2] 9d ab [2] a2 b7 }

  condition:
    any of them
}