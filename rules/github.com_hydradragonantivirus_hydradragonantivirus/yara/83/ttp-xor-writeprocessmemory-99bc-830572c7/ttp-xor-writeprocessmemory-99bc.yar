rule TTP_XOR_WriteProcessMemory_99bc {
  strings:
    $key_99bc = { ce ce [2] fc ec [2] fa d9 [2] d4 d9 [2] eb c5 }

  condition:
    any of them
}