rule TTP_XOR_WriteProcessMemory_8dce {
  strings:
    $key_8dce = { da bc [2] e8 9e [2] ee ab [2] c0 ab [2] ff b7 }

  condition:
    any of them
}