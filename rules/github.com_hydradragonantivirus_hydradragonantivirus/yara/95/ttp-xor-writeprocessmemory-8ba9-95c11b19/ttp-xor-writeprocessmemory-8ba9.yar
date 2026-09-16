rule TTP_XOR_WriteProcessMemory_8ba9 {
  strings:
    $key_8ba9 = { dc db [2] ee f9 [2] e8 cc [2] c6 cc [2] f9 d0 }

  condition:
    any of them
}