rule TTP_XOR_WriteProcessMemory_cdc8 {
  strings:
    $key_cdc8 = { 9a ba [2] a8 98 [2] ae ad [2] 80 ad [2] bf b1 }

  condition:
    any of them
}