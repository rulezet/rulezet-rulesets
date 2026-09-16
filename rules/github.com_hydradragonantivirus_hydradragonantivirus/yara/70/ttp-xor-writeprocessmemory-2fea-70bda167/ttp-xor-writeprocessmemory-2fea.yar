rule TTP_XOR_WriteProcessMemory_2fea {
  strings:
    $key_2fea = { 78 98 [2] 4a ba [2] 4c 8f [2] 62 8f [2] 5d 93 }

  condition:
    any of them
}