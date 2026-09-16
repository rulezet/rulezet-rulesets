rule TTP_XOR_WriteProcessMemory_8be0 {
  strings:
    $key_8be0 = { dc 92 [2] ee b0 [2] e8 85 [2] c6 85 [2] f9 99 }

  condition:
    any of them
}