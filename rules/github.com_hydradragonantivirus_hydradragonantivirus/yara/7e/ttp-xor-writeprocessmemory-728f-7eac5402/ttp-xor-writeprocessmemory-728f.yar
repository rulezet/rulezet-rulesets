rule TTP_XOR_WriteProcessMemory_728f {
  strings:
    $key_728f = { 25 fd [2] 17 df [2] 11 ea [2] 3f ea [2] 00 f6 }

  condition:
    any of them
}