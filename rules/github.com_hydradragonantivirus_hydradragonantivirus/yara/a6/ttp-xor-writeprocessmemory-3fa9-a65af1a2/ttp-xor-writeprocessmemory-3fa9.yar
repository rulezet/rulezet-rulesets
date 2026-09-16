rule TTP_XOR_WriteProcessMemory_3fa9 {
  strings:
    $key_3fa9 = { 68 db [2] 5a f9 [2] 5c cc [2] 72 cc [2] 4d d0 }

  condition:
    any of them
}