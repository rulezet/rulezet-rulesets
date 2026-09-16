rule TTP_XOR_WriteProcessMemory_06a9 {
  strings:
    $key_06a9 = { 51 db [2] 63 f9 [2] 65 cc [2] 4b cc [2] 74 d0 }

  condition:
    any of them
}