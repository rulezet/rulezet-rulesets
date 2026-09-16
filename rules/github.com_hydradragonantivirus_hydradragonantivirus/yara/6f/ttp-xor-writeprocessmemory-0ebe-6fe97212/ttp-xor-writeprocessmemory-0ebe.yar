rule TTP_XOR_WriteProcessMemory_0ebe {
  strings:
    $key_0ebe = { 59 cc [2] 6b ee [2] 6d db [2] 43 db [2] 7c c7 }

  condition:
    any of them
}