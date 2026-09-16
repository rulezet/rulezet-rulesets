rule TTP_XOR_WriteProcessMemory_8dd7 {
  strings:
    $key_8dd7 = { da a5 [2] e8 87 [2] ee b2 [2] c0 b2 [2] ff ae }

  condition:
    any of them
}