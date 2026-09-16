rule TTP_XOR_WriteProcessMemory_43a9 {
  strings:
    $key_43a9 = { 14 db [2] 26 f9 [2] 20 cc [2] 0e cc [2] 31 d0 }

  condition:
    any of them
}