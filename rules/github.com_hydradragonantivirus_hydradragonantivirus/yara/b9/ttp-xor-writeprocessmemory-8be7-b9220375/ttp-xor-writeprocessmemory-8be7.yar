rule TTP_XOR_WriteProcessMemory_8be7 {
  strings:
    $key_8be7 = { dc 95 [2] ee b7 [2] e8 82 [2] c6 82 [2] f9 9e }

  condition:
    any of them
}