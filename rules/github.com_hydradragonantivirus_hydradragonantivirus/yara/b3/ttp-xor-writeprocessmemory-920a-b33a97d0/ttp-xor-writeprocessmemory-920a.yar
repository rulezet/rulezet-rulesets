rule TTP_XOR_WriteProcessMemory_920a {
  strings:
    $key_920a = { c5 78 [2] f7 5a [2] f1 6f [2] df 6f [2] e0 73 }

  condition:
    any of them
}