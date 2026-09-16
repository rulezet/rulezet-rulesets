rule TTP_XOR_WriteProcessMemory_6eea {
  strings:
    $key_6eea = { 39 98 [2] 0b ba [2] 0d 8f [2] 23 8f [2] 1c 93 }

  condition:
    any of them
}