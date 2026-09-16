rule TTP_XOR_WriteProcessMemory_737a {
  strings:
    $key_737a = { 24 08 [2] 16 2a [2] 10 1f [2] 3e 1f [2] 01 03 }

  condition:
    any of them
}