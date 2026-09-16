rule TTP_XOR_WriteProcessMemory_905a {
  strings:
    $key_905a = { c7 28 [2] f5 0a [2] f3 3f [2] dd 3f [2] e2 23 }

  condition:
    any of them
}