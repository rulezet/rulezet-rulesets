rule TTP_XOR_WriteProcessMemory_bdce {
  strings:
    $key_bdce = { ea bc [2] d8 9e [2] de ab [2] f0 ab [2] cf b7 }

  condition:
    any of them
}