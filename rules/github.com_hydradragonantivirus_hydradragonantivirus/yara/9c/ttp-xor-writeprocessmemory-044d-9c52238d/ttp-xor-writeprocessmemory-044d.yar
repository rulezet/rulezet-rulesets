rule TTP_XOR_WriteProcessMemory_044d {
  strings:
    $key_044d = { 53 3f [2] 61 1d [2] 67 28 [2] 49 28 [2] 76 34 }

  condition:
    any of them
}