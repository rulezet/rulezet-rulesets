rule TTP_XOR_WriteProcessMemory_4ea9 {
  strings:
    $key_4ea9 = { 19 db [2] 2b f9 [2] 2d cc [2] 03 cc [2] 3c d0 }

  condition:
    any of them
}