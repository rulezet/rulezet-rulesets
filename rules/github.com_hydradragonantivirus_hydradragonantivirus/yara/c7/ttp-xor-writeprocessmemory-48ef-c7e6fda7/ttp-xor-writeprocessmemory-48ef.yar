rule TTP_XOR_WriteProcessMemory_48ef {
  strings:
    $key_48ef = { 1f 9d [2] 2d bf [2] 2b 8a [2] 05 8a [2] 3a 96 }

  condition:
    any of them
}