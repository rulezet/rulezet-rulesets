rule TTP_XOR_WriteProcessMemory_e0ea {
  strings:
    $key_e0ea = { b7 98 [2] 85 ba [2] 83 8f [2] ad 8f [2] 92 93 }

  condition:
    any of them
}