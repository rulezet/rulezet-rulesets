rule TTP_XOR_WriteProcessMemory_10ce {
  strings:
    $key_10ce = { 47 bc [2] 75 9e [2] 73 ab [2] 5d ab [2] 62 b7 }

  condition:
    any of them
}