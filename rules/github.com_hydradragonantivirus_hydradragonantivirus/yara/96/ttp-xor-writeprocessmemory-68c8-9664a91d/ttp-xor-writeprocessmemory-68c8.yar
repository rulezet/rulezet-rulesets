rule TTP_XOR_WriteProcessMemory_68c8 {
  strings:
    $key_68c8 = { 3f ba [2] 0d 98 [2] 0b ad [2] 25 ad [2] 1a b1 }

  condition:
    any of them
}