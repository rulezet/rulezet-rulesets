rule TTP_XOR_WriteProcessMemory_6a9c {
  strings:
    $key_6a9c = { 3d ee [2] 0f cc [2] 09 f9 [2] 27 f9 [2] 18 e5 }

  condition:
    any of them
}