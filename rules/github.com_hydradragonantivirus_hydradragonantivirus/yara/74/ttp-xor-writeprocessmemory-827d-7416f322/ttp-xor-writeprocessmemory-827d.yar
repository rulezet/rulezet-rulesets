rule TTP_XOR_WriteProcessMemory_827d {
  strings:
    $key_827d = { d5 0f [2] e7 2d [2] e1 18 [2] cf 18 [2] f0 04 }

  condition:
    any of them
}