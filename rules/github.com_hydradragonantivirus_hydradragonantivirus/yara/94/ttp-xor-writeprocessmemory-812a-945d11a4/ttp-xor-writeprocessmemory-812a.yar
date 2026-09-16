rule TTP_XOR_WriteProcessMemory_812a {
  strings:
    $key_812a = { d6 58 [2] e4 7a [2] e2 4f [2] cc 4f [2] f3 53 }

  condition:
    any of them
}