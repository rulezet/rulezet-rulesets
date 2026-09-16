rule TTP_XOR_WriteProcessMemory_3fea {
  strings:
    $key_3fea = { 68 98 [2] 5a ba [2] 5c 8f [2] 72 8f [2] 4d 93 }

  condition:
    any of them
}