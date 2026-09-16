rule TTP_XOR_WriteProcessMemory_3eea {
  strings:
    $key_3eea = { 69 98 [2] 5b ba [2] 5d 8f [2] 73 8f [2] 4c 93 }

  condition:
    any of them
}