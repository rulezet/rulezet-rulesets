rule TTP_XOR_WriteProcessMemory_872f {
  strings:
    $key_872f = { d0 5d [2] e2 7f [2] e4 4a [2] ca 4a [2] f5 56 }

  condition:
    any of them
}