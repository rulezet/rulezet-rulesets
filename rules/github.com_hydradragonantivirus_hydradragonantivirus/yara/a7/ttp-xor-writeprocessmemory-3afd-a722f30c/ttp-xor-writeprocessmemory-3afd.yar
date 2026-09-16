rule TTP_XOR_WriteProcessMemory_3afd {
  strings:
    $key_3afd = { 6d 8f [2] 5f ad [2] 59 98 [2] 77 98 [2] 48 84 }

  condition:
    any of them
}