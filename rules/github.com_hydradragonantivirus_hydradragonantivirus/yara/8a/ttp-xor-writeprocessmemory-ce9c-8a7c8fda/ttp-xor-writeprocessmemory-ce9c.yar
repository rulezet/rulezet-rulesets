rule TTP_XOR_WriteProcessMemory_ce9c {
  strings:
    $key_ce9c = { 99 ee [2] ab cc [2] ad f9 [2] 83 f9 [2] bc e5 }

  condition:
    any of them
}