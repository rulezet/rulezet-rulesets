rule TTP_XOR_WriteProcessMemory_513a {
  strings:
    $key_513a = { 06 48 [2] 34 6a [2] 32 5f [2] 1c 5f [2] 23 43 }

  condition:
    any of them
}