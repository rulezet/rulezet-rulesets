rule TTP_XOR_WriteProcessMemory_8b83 {
  strings:
    $key_8b83 = { dc f1 [2] ee d3 [2] e8 e6 [2] c6 e6 [2] f9 fa }

  condition:
    any of them
}