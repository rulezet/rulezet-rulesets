rule TTP_XOR_WriteProcessMemory_ffa9 {
  strings:
    $key_ffa9 = { a8 db [2] 9a f9 [2] 9c cc [2] b2 cc [2] 8d d0 }

  condition:
    any of them
}