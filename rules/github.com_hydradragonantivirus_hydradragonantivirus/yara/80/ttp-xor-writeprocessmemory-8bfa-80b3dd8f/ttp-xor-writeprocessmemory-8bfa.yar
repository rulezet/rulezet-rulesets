rule TTP_XOR_WriteProcessMemory_8bfa {
  strings:
    $key_8bfa = { dc 88 [2] ee aa [2] e8 9f [2] c6 9f [2] f9 83 }

  condition:
    any of them
}