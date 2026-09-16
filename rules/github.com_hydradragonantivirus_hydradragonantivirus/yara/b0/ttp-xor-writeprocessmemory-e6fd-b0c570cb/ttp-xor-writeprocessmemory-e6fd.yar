rule TTP_XOR_WriteProcessMemory_e6fd {
  strings:
    $key_e6fd = { b1 8f [2] 83 ad [2] 85 98 [2] ab 98 [2] 94 84 }

  condition:
    any of them
}