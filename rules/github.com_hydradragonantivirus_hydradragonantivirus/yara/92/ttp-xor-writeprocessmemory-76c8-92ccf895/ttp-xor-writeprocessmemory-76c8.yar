rule TTP_XOR_WriteProcessMemory_76c8 {
  strings:
    $key_76c8 = { 21 ba [2] 13 98 [2] 15 ad [2] 3b ad [2] 04 b1 }

  condition:
    any of them
}