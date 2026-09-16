rule TTP_XOR_WriteProcessMemory_74ce {
  strings:
    $key_74ce = { 23 bc [2] 11 9e [2] 17 ab [2] 39 ab [2] 06 b7 }

  condition:
    any of them
}