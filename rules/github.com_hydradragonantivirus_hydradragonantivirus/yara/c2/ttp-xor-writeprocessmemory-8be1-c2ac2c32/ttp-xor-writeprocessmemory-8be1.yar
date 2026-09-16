rule TTP_XOR_WriteProcessMemory_8be1 {
  strings:
    $key_8be1 = { dc 93 [2] ee b1 [2] e8 84 [2] c6 84 [2] f9 98 }

  condition:
    any of them
}