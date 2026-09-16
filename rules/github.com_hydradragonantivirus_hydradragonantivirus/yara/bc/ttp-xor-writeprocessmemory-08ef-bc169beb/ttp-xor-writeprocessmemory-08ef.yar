rule TTP_XOR_WriteProcessMemory_08ef {
  strings:
    $key_08ef = { 5f 9d [2] 6d bf [2] 6b 8a [2] 45 8a [2] 7a 96 }

  condition:
    any of them
}