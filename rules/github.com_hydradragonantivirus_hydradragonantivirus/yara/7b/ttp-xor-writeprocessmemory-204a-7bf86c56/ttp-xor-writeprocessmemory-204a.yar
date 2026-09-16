rule TTP_XOR_WriteProcessMemory_204a {
  strings:
    $key_204a = { 77 38 [2] 45 1a [2] 43 2f [2] 6d 2f [2] 52 33 }

  condition:
    any of them
}