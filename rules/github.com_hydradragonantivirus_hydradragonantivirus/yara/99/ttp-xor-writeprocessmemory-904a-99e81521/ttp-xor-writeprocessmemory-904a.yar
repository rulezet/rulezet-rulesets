rule TTP_XOR_WriteProcessMemory_904a {
  strings:
    $key_904a = { c7 38 [2] f5 1a [2] f3 2f [2] dd 2f [2] e2 33 }

  condition:
    any of them
}