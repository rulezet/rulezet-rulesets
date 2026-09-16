rule TTP_XOR_WriteProcessMemory_5bad {
  strings:
    $key_5bad = { 0c df [2] 3e fd [2] 38 c8 [2] 16 c8 [2] 29 d4 }

  condition:
    any of them
}