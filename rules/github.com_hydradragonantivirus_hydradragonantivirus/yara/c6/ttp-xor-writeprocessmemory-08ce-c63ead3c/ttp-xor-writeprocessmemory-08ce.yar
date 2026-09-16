rule TTP_XOR_WriteProcessMemory_08ce {
  strings:
    $key_08ce = { 5f bc [2] 6d 9e [2] 6b ab [2] 45 ab [2] 7a b7 }

  condition:
    any of them
}