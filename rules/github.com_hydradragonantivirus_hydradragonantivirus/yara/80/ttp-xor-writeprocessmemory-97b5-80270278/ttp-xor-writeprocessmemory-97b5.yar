rule TTP_XOR_WriteProcessMemory_97b5 {
  strings:
    $key_97b5 = { c0 c7 [2] f2 e5 [2] f4 d0 [2] da d0 [2] e5 cc }

  condition:
    any of them
}