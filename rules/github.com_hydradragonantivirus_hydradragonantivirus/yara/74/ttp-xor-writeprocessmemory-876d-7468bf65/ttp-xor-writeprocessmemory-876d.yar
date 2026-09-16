rule TTP_XOR_WriteProcessMemory_876d {
  strings:
    $key_876d = { d0 1f [2] e2 3d [2] e4 08 [2] ca 08 [2] f5 14 }

  condition:
    any of them
}