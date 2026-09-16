rule TTP_XOR_WriteProcessMemory_94dc {
  strings:
    $key_94dc = { c3 ae [2] f1 8c [2] f7 b9 [2] d9 b9 [2] e6 a5 }

  condition:
    any of them
}