rule TTP_XOR_WriteProcessMemory_a98c {
  strings:
    $key_a98c = { fe fe [2] cc dc [2] ca e9 [2] e4 e9 [2] db f5 }

  condition:
    any of them
}