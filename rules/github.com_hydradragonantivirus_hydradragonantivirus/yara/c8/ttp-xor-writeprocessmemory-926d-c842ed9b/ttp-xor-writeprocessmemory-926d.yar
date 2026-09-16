rule TTP_XOR_WriteProcessMemory_926d {
  strings:
    $key_926d = { c5 1f [2] f7 3d [2] f1 08 [2] df 08 [2] e0 14 }

  condition:
    any of them
}