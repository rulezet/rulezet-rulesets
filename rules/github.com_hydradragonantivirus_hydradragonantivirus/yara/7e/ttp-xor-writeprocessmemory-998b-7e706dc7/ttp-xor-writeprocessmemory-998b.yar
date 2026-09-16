rule TTP_XOR_WriteProcessMemory_998b {
  strings:
    $key_998b = { ce f9 [2] fc db [2] fa ee [2] d4 ee [2] eb f2 }

  condition:
    any of them
}