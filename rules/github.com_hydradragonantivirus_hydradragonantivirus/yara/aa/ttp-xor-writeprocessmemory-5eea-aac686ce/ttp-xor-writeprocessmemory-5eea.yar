rule TTP_XOR_WriteProcessMemory_5eea {
  strings:
    $key_5eea = { 09 98 [2] 3b ba [2] 3d 8f [2] 13 8f [2] 2c 93 }

  condition:
    any of them
}