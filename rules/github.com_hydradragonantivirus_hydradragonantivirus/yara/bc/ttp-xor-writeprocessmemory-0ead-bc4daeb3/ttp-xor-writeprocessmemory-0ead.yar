rule TTP_XOR_WriteProcessMemory_0ead {
  strings:
    $key_0ead = { 59 df [2] 6b fd [2] 6d c8 [2] 43 c8 [2] 7c d4 }

  condition:
    any of them
}