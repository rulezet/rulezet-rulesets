rule TTP_XOR_WriteProcessMemory_94b5 {
  strings:
    $key_94b5 = { c3 c7 [2] f1 e5 [2] f7 d0 [2] d9 d0 [2] e6 cc }

  condition:
    any of them
}