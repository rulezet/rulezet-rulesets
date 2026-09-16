rule TTP_XOR_WriteProcessMemory_8ba4 {
  strings:
    $key_8ba4 = { dc d6 [2] ee f4 [2] e8 c1 [2] c6 c1 [2] f9 dd }

  condition:
    any of them
}