rule TTP_XOR_WriteProcessMemory_054a {
  strings:
    $key_054a = { 52 38 [2] 60 1a [2] 66 2f [2] 48 2f [2] 77 33 }

  condition:
    any of them
}