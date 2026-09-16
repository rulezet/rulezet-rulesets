rule TTP_XOR_WriteProcessMemory_4bad {
  strings:
    $key_4bad = { 1c df [2] 2e fd [2] 28 c8 [2] 06 c8 [2] 39 d4 }

  condition:
    any of them
}