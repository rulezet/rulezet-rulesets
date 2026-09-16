rule TTP_XOR_WriteProcessMemory_701b {
  strings:
    $key_701b = { 27 69 [2] 15 4b [2] 13 7e [2] 3d 7e [2] 02 62 }

  condition:
    any of them
}