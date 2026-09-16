rule TTP_XOR_WriteProcessMemory_8bac {
  strings:
    $key_8bac = { dc de [2] ee fc [2] e8 c9 [2] c6 c9 [2] f9 d5 }

  condition:
    any of them
}