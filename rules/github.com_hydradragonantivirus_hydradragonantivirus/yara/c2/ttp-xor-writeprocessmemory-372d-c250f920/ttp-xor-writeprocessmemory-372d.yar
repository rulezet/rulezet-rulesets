rule TTP_XOR_WriteProcessMemory_372d {
  strings:
    $key_372d = { 60 5f [2] 52 7d [2] 54 48 [2] 7a 48 [2] 45 54 }

  condition:
    any of them
}