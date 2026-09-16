rule TTP_XOR_WriteProcessMemory_863b {
  strings:
    $key_863b = { d1 49 [2] e3 6b [2] e5 5e [2] cb 5e [2] f4 42 }

  condition:
    any of them
}