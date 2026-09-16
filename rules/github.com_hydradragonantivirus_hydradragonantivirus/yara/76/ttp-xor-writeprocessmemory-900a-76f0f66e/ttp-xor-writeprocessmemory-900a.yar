rule TTP_XOR_WriteProcessMemory_900a {
  strings:
    $key_900a = { c7 78 [2] f5 5a [2] f3 6f [2] dd 6f [2] e2 73 }

  condition:
    any of them
}