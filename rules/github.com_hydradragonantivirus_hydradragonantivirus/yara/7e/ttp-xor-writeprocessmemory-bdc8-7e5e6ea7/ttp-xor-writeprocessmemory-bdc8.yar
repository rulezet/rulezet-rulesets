rule TTP_XOR_WriteProcessMemory_bdc8 {
  strings:
    $key_bdc8 = { ea ba [2] d8 98 [2] de ad [2] f0 ad [2] cf b1 }

  condition:
    any of them
}