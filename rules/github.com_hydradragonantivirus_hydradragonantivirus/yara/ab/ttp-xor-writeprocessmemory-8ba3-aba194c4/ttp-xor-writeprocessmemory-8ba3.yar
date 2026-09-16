rule TTP_XOR_WriteProcessMemory_8ba3 {
  strings:
    $key_8ba3 = { dc d1 [2] ee f3 [2] e8 c6 [2] c6 c6 [2] f9 da }

  condition:
    any of them
}