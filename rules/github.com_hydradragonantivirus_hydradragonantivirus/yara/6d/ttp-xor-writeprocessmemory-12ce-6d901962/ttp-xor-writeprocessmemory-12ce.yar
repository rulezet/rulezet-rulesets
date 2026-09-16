rule TTP_XOR_WriteProcessMemory_12ce {
  strings:
    $key_12ce = { 45 bc [2] 77 9e [2] 71 ab [2] 5f ab [2] 60 b7 }

  condition:
    any of them
}