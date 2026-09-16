rule TTP_XOR_WriteProcessMemory_38ef {
  strings:
    $key_38ef = { 6f 9d [2] 5d bf [2] 5b 8a [2] 75 8a [2] 4a 96 }

  condition:
    any of them
}