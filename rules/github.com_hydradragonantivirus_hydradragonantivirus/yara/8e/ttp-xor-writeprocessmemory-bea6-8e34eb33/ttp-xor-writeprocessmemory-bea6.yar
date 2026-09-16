rule TTP_XOR_WriteProcessMemory_bea6 {
  strings:
    $key_bea6 = { e9 d4 [2] db f6 [2] dd c3 [2] f3 c3 [2] cc df }

  condition:
    any of them
}