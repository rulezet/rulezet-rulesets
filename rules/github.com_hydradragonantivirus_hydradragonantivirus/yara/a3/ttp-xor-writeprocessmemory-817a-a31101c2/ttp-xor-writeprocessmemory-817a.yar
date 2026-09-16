rule TTP_XOR_WriteProcessMemory_817a {
  strings:
    $key_817a = { d6 08 [2] e4 2a [2] e2 1f [2] cc 1f [2] f3 03 }

  condition:
    any of them
}