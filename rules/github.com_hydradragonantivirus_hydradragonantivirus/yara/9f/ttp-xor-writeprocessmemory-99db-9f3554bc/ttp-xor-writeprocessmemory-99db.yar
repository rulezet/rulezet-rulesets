rule TTP_XOR_WriteProcessMemory_99db {
  strings:
    $key_99db = { ce a9 [2] fc 8b [2] fa be [2] d4 be [2] eb a2 }

  condition:
    any of them
}