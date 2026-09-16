rule TTP_XOR_WriteProcessMemory_6ead {
  strings:
    $key_6ead = { 39 df [2] 0b fd [2] 0d c8 [2] 23 c8 [2] 1c d4 }

  condition:
    any of them
}