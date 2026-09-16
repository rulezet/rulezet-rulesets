rule TTP_XOR_WriteProcessMemory_3ead {
  strings:
    $key_3ead = { 69 df [2] 5b fd [2] 5d c8 [2] 73 c8 [2] 4c d4 }

  condition:
    any of them
}