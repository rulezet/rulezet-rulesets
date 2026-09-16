rule TTP_XOR_WriteProcessMemory_5cdd {
  strings:
    $key_5cdd = { 0b af [2] 39 8d [2] 3f b8 [2] 11 b8 [2] 2e a4 }

  condition:
    any of them
}