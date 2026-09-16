rule TTP_XOR_WriteProcessMemory_ddc8 {
  strings:
    $key_ddc8 = { 8a ba [2] b8 98 [2] be ad [2] 90 ad [2] af b1 }

  condition:
    any of them
}