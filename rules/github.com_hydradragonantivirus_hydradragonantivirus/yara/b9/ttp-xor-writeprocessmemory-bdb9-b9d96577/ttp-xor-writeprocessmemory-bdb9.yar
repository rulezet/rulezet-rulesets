rule TTP_XOR_WriteProcessMemory_bdb9 {
  strings:
    $key_bdb9 = { ea cb [2] d8 e9 [2] de dc [2] f0 dc [2] cf c0 }

  condition:
    any of them
}