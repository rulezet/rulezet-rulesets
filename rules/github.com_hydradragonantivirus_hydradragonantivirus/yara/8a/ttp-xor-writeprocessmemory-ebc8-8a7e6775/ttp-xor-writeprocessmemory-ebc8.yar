rule TTP_XOR_WriteProcessMemory_ebc8 {
  strings:
    $key_ebc8 = { bc ba [2] 8e 98 [2] 88 ad [2] a6 ad [2] 99 b1 }

  condition:
    any of them
}