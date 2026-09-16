rule TTP_XOR_WriteProcessMemory_871d {
  strings:
    $key_871d = { d0 6f [2] e2 4d [2] e4 78 [2] ca 78 [2] f5 64 }

  condition:
    any of them
}