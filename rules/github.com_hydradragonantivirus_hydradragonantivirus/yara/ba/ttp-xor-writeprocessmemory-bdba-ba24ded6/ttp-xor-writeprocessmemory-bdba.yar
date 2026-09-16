rule TTP_XOR_WriteProcessMemory_bdba {
  strings:
    $key_bdba = { ea c8 [2] d8 ea [2] de df [2] f0 df [2] cf c3 }

  condition:
    any of them
}