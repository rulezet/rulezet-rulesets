rule TTP_XOR_WriteProcessMemory_674a {
  strings:
    $key_674a = { 30 38 [2] 02 1a [2] 04 2f [2] 2a 2f [2] 15 33 }

  condition:
    any of them
}