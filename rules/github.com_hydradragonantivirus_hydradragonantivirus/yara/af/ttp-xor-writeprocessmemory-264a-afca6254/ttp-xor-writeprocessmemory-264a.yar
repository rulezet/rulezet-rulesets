rule TTP_XOR_WriteProcessMemory_264a {
  strings:
    $key_264a = { 71 38 [2] 43 1a [2] 45 2f [2] 6b 2f [2] 54 33 }

  condition:
    any of them
}