rule TTP_XOR_WriteProcessMemory_949c {
  strings:
    $key_949c = { c3 ee [2] f1 cc [2] f7 f9 [2] d9 f9 [2] e6 e5 }

  condition:
    any of them
}