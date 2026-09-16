rule TTP_XOR_WriteProcessMemory_80ce {
  strings:
    $key_80ce = { d7 bc [2] e5 9e [2] e3 ab [2] cd ab [2] f2 b7 }

  condition:
    any of them
}