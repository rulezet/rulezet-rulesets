rule TTP_XOR_WriteProcessMemory_812f {
  strings:
    $key_812f = { d6 5d [2] e4 7f [2] e2 4a [2] cc 4a [2] f3 56 }

  condition:
    any of them
}