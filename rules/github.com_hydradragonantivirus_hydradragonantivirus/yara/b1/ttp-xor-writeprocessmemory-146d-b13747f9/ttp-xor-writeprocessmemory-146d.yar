rule TTP_XOR_WriteProcessMemory_146d {
  strings:
    $key_146d = { 43 1f [2] 71 3d [2] 77 08 [2] 59 08 [2] 66 14 }

  condition:
    any of them
}