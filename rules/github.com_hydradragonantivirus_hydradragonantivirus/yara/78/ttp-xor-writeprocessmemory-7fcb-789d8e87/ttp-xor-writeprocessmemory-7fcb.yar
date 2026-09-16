rule TTP_XOR_WriteProcessMemory_7fcb {
  strings:
    $key_7fcb = { 28 b9 [2] 1a 9b [2] 1c ae [2] 32 ae [2] 0d b2 }

  condition:
    any of them
}