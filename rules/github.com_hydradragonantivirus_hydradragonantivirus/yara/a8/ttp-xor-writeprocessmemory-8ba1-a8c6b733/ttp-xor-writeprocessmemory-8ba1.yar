rule TTP_XOR_WriteProcessMemory_8ba1 {
  strings:
    $key_8ba1 = { dc d3 [2] ee f1 [2] e8 c4 [2] c6 c4 [2] f9 d8 }

  condition:
    any of them
}