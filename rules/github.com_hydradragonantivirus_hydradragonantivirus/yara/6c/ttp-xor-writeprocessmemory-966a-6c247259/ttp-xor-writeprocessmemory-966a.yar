rule TTP_XOR_WriteProcessMemory_966a {
  strings:
    $key_966a = { c1 18 [2] f3 3a [2] f5 0f [2] db 0f [2] e4 13 }

  condition:
    any of them
}