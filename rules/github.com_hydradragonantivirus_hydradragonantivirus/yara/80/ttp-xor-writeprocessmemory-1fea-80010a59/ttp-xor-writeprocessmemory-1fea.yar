rule TTP_XOR_WriteProcessMemory_1fea {
  strings:
    $key_1fea = { 48 98 [2] 7a ba [2] 7c 8f [2] 52 8f [2] 6d 93 }

  condition:
    any of them
}