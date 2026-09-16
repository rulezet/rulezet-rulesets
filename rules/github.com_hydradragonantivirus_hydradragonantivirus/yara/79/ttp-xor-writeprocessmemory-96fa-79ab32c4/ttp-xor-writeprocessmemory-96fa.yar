rule TTP_XOR_WriteProcessMemory_96fa {
  strings:
    $key_96fa = { c1 88 [2] f3 aa [2] f5 9f [2] db 9f [2] e4 83 }

  condition:
    any of them
}