rule TTP_XOR_WriteProcessMemory_73ce {
  strings:
    $key_73ce = { 24 bc [2] 16 9e [2] 10 ab [2] 3e ab [2] 01 b7 }

  condition:
    any of them
}