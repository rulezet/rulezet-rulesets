rule TTP_XOR_WriteProcessMemory_815d {
  strings:
    $key_815d = { d6 2f [2] e4 0d [2] e2 38 [2] cc 38 [2] f3 24 }

  condition:
    any of them
}