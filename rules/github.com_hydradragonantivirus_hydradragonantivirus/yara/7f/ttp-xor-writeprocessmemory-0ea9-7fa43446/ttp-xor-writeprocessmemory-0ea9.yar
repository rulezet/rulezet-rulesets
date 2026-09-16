rule TTP_XOR_WriteProcessMemory_0ea9 {
  strings:
    $key_0ea9 = { 59 db [2] 6b f9 [2] 6d cc [2] 43 cc [2] 7c d0 }

  condition:
    any of them
}