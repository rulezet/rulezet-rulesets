rule TTP_XOR_WriteProcessMemory_f8a9 {
  strings:
    $key_f8a9 = { af db [2] 9d f9 [2] 9b cc [2] b5 cc [2] 8a d0 }

  condition:
    any of them
}