rule TTP_XOR_WriteProcessMemory_2fba {
  strings:
    $key_2fba = { 78 c8 [2] 4a ea [2] 4c df [2] 62 df [2] 5d c3 }

  condition:
    any of them
}