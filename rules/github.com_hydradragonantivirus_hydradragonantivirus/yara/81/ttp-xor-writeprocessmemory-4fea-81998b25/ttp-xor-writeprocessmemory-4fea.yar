rule TTP_XOR_WriteProcessMemory_4fea {
  strings:
    $key_4fea = { 18 98 [2] 2a ba [2] 2c 8f [2] 02 8f [2] 3d 93 }

  condition:
    any of them
}