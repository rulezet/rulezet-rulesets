rule TTP_XOR_WriteProcessMemory_8bba {
  strings:
    $key_8bba = { dc c8 [2] ee ea [2] e8 df [2] c6 df [2] f9 c3 }

  condition:
    any of them
}