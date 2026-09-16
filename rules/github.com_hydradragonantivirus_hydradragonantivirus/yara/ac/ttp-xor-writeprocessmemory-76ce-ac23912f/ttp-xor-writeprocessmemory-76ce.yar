rule TTP_XOR_WriteProcessMemory_76ce {
  strings:
    $key_76ce = { 21 bc [2] 13 9e [2] 15 ab [2] 3b ab [2] 04 b7 }

  condition:
    any of them
}