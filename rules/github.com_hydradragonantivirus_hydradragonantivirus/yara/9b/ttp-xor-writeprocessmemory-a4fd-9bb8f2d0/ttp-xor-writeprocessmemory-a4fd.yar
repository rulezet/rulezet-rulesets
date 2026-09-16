rule TTP_XOR_WriteProcessMemory_a4fd {
  strings:
    $key_a4fd = { f3 8f [2] c1 ad [2] c7 98 [2] e9 98 [2] d6 84 }

  condition:
    any of them
}