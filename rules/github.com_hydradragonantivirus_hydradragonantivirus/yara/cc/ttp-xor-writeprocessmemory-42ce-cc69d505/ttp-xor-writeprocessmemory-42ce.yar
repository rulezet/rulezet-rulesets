rule TTP_XOR_WriteProcessMemory_42ce {
  strings:
    $key_42ce = { 15 bc [2] 27 9e [2] 21 ab [2] 0f ab [2] 30 b7 }

  condition:
    any of them
}