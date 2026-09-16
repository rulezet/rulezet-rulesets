rule TTP_XOR_WriteProcessMemory_92dc {
  strings:
    $key_92dc = { c5 ae [2] f7 8c [2] f1 b9 [2] df b9 [2] e0 a5 }

  condition:
    any of them
}