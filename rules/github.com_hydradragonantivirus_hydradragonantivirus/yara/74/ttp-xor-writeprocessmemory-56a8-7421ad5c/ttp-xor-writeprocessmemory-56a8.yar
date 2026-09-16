rule TTP_XOR_WriteProcessMemory_56a8 {
  strings:
    $key_56a8 = { 01 da [2] 33 f8 [2] 35 cd [2] 1b cd [2] 24 d1 }

  condition:
    any of them
}