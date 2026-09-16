rule TTP_XOR_WriteProcessMemory_99ae {
  strings:
    $key_99ae = { ce dc [2] fc fe [2] fa cb [2] d4 cb [2] eb d7 }

  condition:
    any of them
}