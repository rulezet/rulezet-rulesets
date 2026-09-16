rule TTP_XOR_WriteProcessMemory_2fa9 {
  strings:
    $key_2fa9 = { 78 db [2] 4a f9 [2] 4c cc [2] 62 cc [2] 5d d0 }

  condition:
    any of them
}