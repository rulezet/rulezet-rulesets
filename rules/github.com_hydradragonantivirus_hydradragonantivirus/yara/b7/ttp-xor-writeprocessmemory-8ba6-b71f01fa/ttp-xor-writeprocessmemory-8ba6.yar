rule TTP_XOR_WriteProcessMemory_8ba6 {
  strings:
    $key_8ba6 = { dc d4 [2] ee f6 [2] e8 c3 [2] c6 c3 [2] f9 df }

  condition:
    any of them
}