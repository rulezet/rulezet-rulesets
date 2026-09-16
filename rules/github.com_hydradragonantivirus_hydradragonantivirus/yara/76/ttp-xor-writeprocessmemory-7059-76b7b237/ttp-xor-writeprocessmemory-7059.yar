rule TTP_XOR_WriteProcessMemory_7059 {
  strings:
    $key_7059 = { 27 2b [2] 15 09 [2] 13 3c [2] 3d 3c [2] 02 20 }

  condition:
    any of them
}