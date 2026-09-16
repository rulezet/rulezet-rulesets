rule TTP_XOR_WriteProcessMemory_707b {
  strings:
    $key_707b = { 27 09 [2] 15 2b [2] 13 1e [2] 3d 1e [2] 02 02 }

  condition:
    any of them
}