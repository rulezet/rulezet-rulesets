rule TTP_XOR_WriteProcessMemory_ce8c {
  strings:
    $key_ce8c = { 99 fe [2] ab dc [2] ad e9 [2] 83 e9 [2] bc f5 }

  condition:
    any of them
}