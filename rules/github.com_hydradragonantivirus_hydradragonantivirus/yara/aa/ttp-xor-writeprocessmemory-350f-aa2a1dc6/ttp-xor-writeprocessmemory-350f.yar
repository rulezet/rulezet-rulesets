rule TTP_XOR_WriteProcessMemory_350f {
  strings:
    $key_350f = { 62 7d [2] 50 5f [2] 56 6a [2] 78 6a [2] 47 76 }

  condition:
    any of them
}