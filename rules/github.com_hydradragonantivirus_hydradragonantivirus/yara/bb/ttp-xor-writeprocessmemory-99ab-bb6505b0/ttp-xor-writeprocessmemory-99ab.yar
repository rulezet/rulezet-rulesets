rule TTP_XOR_WriteProcessMemory_99ab {
  strings:
    $key_99ab = { ce d9 [2] fc fb [2] fa ce [2] d4 ce [2] eb d2 }

  condition:
    any of them
}