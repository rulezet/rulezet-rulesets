rule TTP_XOR_WriteProcessMemory_aafd {
  strings:
    $key_aafd = { fd 8f [2] cf ad [2] c9 98 [2] e7 98 [2] d8 84 }

  condition:
    any of them
}