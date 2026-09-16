rule TTP_XOR_WriteProcessMemory_6a1b {
  strings:
    $key_6a1b = { 3d 69 [2] 0f 4b [2] 09 7e [2] 27 7e [2] 18 62 }

  condition:
    any of them
}