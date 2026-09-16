rule TTP_XOR_WriteProcessMemory_ce8d {
  strings:
    $key_ce8d = { 99 ff [2] ab dd [2] ad e8 [2] 83 e8 [2] bc f4 }

  condition:
    any of them
}