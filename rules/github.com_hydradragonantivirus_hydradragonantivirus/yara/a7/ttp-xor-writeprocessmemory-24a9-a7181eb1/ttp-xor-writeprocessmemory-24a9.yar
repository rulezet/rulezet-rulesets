rule TTP_XOR_WriteProcessMemory_24a9 {
  strings:
    $key_24a9 = { 73 db [2] 41 f9 [2] 47 cc [2] 69 cc [2] 56 d0 }

  condition:
    any of them
}