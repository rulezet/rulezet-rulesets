rule TTP_XOR_WriteProcessMemory_7019 {
  strings:
    $key_7019 = { 27 6b [2] 15 49 [2] 13 7c [2] 3d 7c [2] 02 60 }

  condition:
    any of them
}