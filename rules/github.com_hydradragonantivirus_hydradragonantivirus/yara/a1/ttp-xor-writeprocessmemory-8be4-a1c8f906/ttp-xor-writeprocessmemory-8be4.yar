rule TTP_XOR_WriteProcessMemory_8be4 {
  strings:
    $key_8be4 = { dc 96 [2] ee b4 [2] e8 81 [2] c6 81 [2] f9 9d }

  condition:
    any of them
}