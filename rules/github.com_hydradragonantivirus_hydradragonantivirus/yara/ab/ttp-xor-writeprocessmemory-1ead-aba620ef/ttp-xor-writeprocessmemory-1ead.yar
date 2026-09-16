rule TTP_XOR_WriteProcessMemory_1ead {
  strings:
    $key_1ead = { 49 df [2] 7b fd [2] 7d c8 [2] 53 c8 [2] 6c d4 }

  condition:
    any of them
}