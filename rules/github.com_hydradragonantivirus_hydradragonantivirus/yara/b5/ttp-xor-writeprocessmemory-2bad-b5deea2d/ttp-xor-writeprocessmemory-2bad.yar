rule TTP_XOR_WriteProcessMemory_2bad {
  strings:
    $key_2bad = { 7c df [2] 4e fd [2] 48 c8 [2] 66 c8 [2] 59 d4 }

  condition:
    any of them
}