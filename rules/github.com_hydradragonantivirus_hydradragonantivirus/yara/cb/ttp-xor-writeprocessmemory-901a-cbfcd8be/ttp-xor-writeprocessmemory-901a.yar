rule TTP_XOR_WriteProcessMemory_901a {
  strings:
    $key_901a = { c7 68 [2] f5 4a [2] f3 7f [2] dd 7f [2] e2 63 }

  condition:
    any of them
}