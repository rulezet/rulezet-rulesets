rule TTP_XOR_WriteProcessMemory_99be {
  strings:
    $key_99be = { ce cc [2] fc ee [2] fa db [2] d4 db [2] eb c7 }

  condition:
    any of them
}