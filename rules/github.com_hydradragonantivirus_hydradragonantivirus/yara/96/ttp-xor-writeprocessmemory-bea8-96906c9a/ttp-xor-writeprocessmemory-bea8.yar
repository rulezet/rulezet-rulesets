rule TTP_XOR_WriteProcessMemory_bea8 {
  strings:
    $key_bea8 = { e9 da [2] db f8 [2] dd cd [2] f3 cd [2] cc d1 }

  condition:
    any of them
}