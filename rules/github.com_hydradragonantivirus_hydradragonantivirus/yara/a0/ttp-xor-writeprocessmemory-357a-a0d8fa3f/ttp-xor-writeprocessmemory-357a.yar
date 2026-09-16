rule TTP_XOR_WriteProcessMemory_357a {
  strings:
    $key_357a = { 62 08 [2] 50 2a [2] 56 1f [2] 78 1f [2] 47 03 }

  condition:
    any of them
}