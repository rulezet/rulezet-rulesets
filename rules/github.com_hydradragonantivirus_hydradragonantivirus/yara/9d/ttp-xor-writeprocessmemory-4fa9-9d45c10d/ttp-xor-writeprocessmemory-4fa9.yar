rule TTP_XOR_WriteProcessMemory_4fa9 {
  strings:
    $key_4fa9 = { 18 db [2] 2a f9 [2] 2c cc [2] 02 cc [2] 3d d0 }

  condition:
    any of them
}