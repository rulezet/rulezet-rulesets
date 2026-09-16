rule TTP_XOR_WriteProcessMemory_93dc {
  strings:
    $key_93dc = { c4 ae [2] f6 8c [2] f0 b9 [2] de b9 [2] e1 a5 }

  condition:
    any of them
}