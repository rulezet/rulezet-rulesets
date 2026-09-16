rule TTP_XOR_WriteProcessMemory_0fea {
  strings:
    $key_0fea = { 58 98 [2] 6a ba [2] 6c 8f [2] 42 8f [2] 7d 93 }

  condition:
    any of them
}