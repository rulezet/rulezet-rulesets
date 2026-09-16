rule TTP_XOR_WriteProcessMemory_8efd {
  strings:
    $key_8efd = { d9 8f [2] eb ad [2] ed 98 [2] c3 98 [2] fc 84 }

  condition:
    any of them
}