rule TTP_XOR_WriteProcessMemory_923f {
  strings:
    $key_923f = { c5 4d [2] f7 6f [2] f1 5a [2] df 5a [2] e0 46 }

  condition:
    any of them
}