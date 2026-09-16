rule TTP_XOR_WriteProcessMemory_93b5 {
  strings:
    $key_93b5 = { c4 c7 [2] f6 e5 [2] f0 d0 [2] de d0 [2] e1 cc }

  condition:
    any of them
}