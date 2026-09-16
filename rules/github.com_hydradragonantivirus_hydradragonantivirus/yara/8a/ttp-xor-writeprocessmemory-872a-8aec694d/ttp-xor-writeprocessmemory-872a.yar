rule TTP_XOR_WriteProcessMemory_872a {
  strings:
    $key_872a = { d0 58 [2] e2 7a [2] e4 4f [2] ca 4f [2] f5 53 }

  condition:
    any of them
}