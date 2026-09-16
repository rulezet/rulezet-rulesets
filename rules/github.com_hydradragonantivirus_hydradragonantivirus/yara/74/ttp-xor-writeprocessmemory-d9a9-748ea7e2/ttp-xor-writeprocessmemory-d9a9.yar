rule TTP_XOR_WriteProcessMemory_d9a9 {
  strings:
    $key_d9a9 = { 8e db [2] bc f9 [2] ba cc [2] 94 cc [2] ab d0 }

  condition:
    any of them
}