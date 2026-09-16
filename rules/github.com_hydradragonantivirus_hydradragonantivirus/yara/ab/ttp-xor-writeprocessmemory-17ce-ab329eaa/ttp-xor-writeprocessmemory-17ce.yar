rule TTP_XOR_WriteProcessMemory_17ce {
  strings:
    $key_17ce = { 40 bc [2] 72 9e [2] 74 ab [2] 5a ab [2] 65 b7 }

  condition:
    any of them
}