rule TTP_XOR_WriteProcessMemory_e5fd {
  strings:
    $key_e5fd = { b2 8f [2] 80 ad [2] 86 98 [2] a8 98 [2] 97 84 }

  condition:
    any of them
}