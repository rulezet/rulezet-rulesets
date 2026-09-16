rule TTP_XOR_WriteProcessMemory_45ce {
  strings:
    $key_45ce = { 12 bc [2] 20 9e [2] 26 ab [2] 08 ab [2] 37 b7 }

  condition:
    any of them
}