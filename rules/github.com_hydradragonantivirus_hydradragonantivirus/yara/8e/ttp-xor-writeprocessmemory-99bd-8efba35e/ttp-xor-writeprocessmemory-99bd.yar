rule TTP_XOR_WriteProcessMemory_99bd {
  strings:
    $key_99bd = { ce cf [2] fc ed [2] fa d8 [2] d4 d8 [2] eb c4 }

  condition:
    any of them
}