rule TTP_XOR_WriteProcessMemory_7fba {
  strings:
    $key_7fba = { 28 c8 [2] 1a ea [2] 1c df [2] 32 df [2] 0d c3 }

  condition:
    any of them
}