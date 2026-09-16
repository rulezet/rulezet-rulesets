rule TTP_XOR_WriteProcessMemory_99dd {
  strings:
    $key_99dd = { ce af [2] fc 8d [2] fa b8 [2] d4 b8 [2] eb a4 }

  condition:
    any of them
}