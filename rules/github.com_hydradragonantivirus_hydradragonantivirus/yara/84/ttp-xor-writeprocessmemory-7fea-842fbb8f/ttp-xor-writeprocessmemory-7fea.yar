rule TTP_XOR_WriteProcessMemory_7fea {
  strings:
    $key_7fea = { 28 98 [2] 1a ba [2] 1c 8f [2] 32 8f [2] 0d 93 }

  condition:
    any of them
}