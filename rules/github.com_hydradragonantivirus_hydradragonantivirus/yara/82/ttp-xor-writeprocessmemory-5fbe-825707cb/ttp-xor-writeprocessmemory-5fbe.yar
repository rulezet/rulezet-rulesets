rule TTP_XOR_WriteProcessMemory_5fbe {
  strings:
    $key_5fbe = { 08 cc [2] 3a ee [2] 3c db [2] 12 db [2] 2d c7 }

  condition:
    any of them
}