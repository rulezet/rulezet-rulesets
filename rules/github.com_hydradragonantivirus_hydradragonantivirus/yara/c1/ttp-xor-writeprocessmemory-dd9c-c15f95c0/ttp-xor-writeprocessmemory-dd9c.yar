rule TTP_XOR_WriteProcessMemory_dd9c {
  strings:
    $key_dd9c = { 8a ee [2] b8 cc [2] be f9 [2] 90 f9 [2] af e5 }

  condition:
    any of them
}