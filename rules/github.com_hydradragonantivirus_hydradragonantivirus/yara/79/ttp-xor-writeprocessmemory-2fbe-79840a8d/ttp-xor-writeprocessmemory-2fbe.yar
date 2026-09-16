rule TTP_XOR_WriteProcessMemory_2fbe {
  strings:
    $key_2fbe = { 78 cc [2] 4a ee [2] 4c db [2] 62 db [2] 5d c7 }

  condition:
    any of them
}