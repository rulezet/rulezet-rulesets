rule TTP_XOR_WriteProcessMemory_28c8 {
  strings:
    $key_28c8 = { 7f ba [2] 4d 98 [2] 4b ad [2] 65 ad [2] 5a b1 }

  condition:
    any of them
}