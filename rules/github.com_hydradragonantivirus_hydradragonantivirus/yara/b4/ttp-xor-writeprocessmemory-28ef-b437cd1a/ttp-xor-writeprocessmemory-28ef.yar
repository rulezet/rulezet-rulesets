rule TTP_XOR_WriteProcessMemory_28ef {
  strings:
    $key_28ef = { 7f 9d [2] 4d bf [2] 4b 8a [2] 65 8a [2] 5a 96 }

  condition:
    any of them
}