rule TTP_XOR_WriteProcessMemory_346a {
  strings:
    $key_346a = { 63 18 [2] 51 3a [2] 57 0f [2] 79 0f [2] 46 13 }

  condition:
    any of them
}