rule TTP_XOR_WriteProcessMemory_6a2b {
  strings:
    $key_6a2b = { 3d 59 [2] 0f 7b [2] 09 4e [2] 27 4e [2] 18 52 }

  condition:
    any of them
}