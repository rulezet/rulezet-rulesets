rule TTP_XOR_WriteProcessMemory_7ea9 {
  strings:
    $key_7ea9 = { 29 db [2] 1b f9 [2] 1d cc [2] 33 cc [2] 0c d0 }

  condition:
    any of them
}