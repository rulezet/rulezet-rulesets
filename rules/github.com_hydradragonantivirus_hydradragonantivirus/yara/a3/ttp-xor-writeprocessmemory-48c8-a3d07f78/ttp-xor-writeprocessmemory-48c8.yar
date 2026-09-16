rule TTP_XOR_WriteProcessMemory_48c8 {
  strings:
    $key_48c8 = { 1f ba [2] 2d 98 [2] 2b ad [2] 05 ad [2] 3a b1 }

  condition:
    any of them
}