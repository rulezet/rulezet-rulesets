rule TTP_XOR_WriteProcessMemory_2fcb {
  strings:
    $key_2fcb = { 78 b9 [2] 4a 9b [2] 4c ae [2] 62 ae [2] 5d b2 }

  condition:
    any of them
}