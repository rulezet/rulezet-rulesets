rule TTP_XOR_WriteProcessMemory_8dd4 {
  strings:
    $key_8dd4 = { da a6 [2] e8 84 [2] ee b1 [2] c0 b1 [2] ff ad }

  condition:
    any of them
}