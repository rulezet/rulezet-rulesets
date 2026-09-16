rule TTP_XOR_WriteProcessMemory_ce8a {
  strings:
    $key_ce8a = { 99 f8 [2] ab da [2] ad ef [2] 83 ef [2] bc f3 }

  condition:
    any of them
}