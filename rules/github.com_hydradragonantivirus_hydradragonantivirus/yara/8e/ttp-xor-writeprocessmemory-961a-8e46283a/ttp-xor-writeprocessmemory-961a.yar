rule TTP_XOR_WriteProcessMemory_961a {
  strings:
    $key_961a = { c1 68 [2] f3 4a [2] f5 7f [2] db 7f [2] e4 63 }

  condition:
    any of them
}