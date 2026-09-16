rule TTP_XOR_WriteProcessMemory_5ebe {
  strings:
    $key_5ebe = { 09 cc [2] 3b ee [2] 3d db [2] 13 db [2] 2c c7 }

  condition:
    any of them
}