rule TTP_XOR_WriteProcessMemory_80dc {
  strings:
    $key_80dc = { d7 ae [2] e5 8c [2] e3 b9 [2] cd b9 [2] f2 a5 }

  condition:
    any of them
}