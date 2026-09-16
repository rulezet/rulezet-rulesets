rule TTP_XOR_WriteProcessMemory_29c8 {
  strings:
    $key_29c8 = { 7e ba [2] 4c 98 [2] 4a ad [2] 64 ad [2] 5b b1 }

  condition:
    any of them
}