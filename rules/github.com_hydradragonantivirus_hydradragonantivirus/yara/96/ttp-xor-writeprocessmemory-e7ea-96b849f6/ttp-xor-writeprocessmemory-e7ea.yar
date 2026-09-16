rule TTP_XOR_WriteProcessMemory_e7ea {
  strings:
    $key_e7ea = { b0 98 [2] 82 ba [2] 84 8f [2] aa 8f [2] 95 93 }

  condition:
    any of them
}