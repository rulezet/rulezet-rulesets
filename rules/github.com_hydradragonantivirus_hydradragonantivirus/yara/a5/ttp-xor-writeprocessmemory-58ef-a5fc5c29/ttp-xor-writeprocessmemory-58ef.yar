rule TTP_XOR_WriteProcessMemory_58ef {
  strings:
    $key_58ef = { 0f 9d [2] 3d bf [2] 3b 8a [2] 15 8a [2] 2a 96 }

  condition:
    any of them
}