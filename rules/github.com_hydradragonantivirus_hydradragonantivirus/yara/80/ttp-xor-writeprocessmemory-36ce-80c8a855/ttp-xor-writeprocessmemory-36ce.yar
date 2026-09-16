rule TTP_XOR_WriteProcessMemory_36ce {
  strings:
    $key_36ce = { 61 bc [2] 53 9e [2] 55 ab [2] 7b ab [2] 44 b7 }

  condition:
    any of them
}