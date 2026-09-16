rule TTP_XOR_WriteProcessMemory_863c {
  strings:
    $key_863c = { d1 4e [2] e3 6c [2] e5 59 [2] cb 59 [2] f4 45 }

  condition:
    any of them
}