rule TTP_XOR_WriteProcessMemory_ce8b {
  strings:
    $key_ce8b = { 99 f9 [2] ab db [2] ad ee [2] 83 ee [2] bc f2 }

  condition:
    any of them
}