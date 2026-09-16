rule TTP_XOR_WriteProcessMemory_871f {
  strings:
    $key_871f = { d0 6d [2] e2 4f [2] e4 7a [2] ca 7a [2] f5 66 }

  condition:
    any of them
}