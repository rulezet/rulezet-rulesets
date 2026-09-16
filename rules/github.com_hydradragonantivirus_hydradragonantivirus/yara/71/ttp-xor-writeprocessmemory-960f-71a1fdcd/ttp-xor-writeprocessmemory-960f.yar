rule TTP_XOR_WriteProcessMemory_960f {
  strings:
    $key_960f = { c1 7d [2] f3 5f [2] f5 6a [2] db 6a [2] e4 76 }

  condition:
    any of them
}