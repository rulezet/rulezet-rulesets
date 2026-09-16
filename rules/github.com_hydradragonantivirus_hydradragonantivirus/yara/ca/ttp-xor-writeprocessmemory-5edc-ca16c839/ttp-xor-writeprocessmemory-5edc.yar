rule TTP_XOR_WriteProcessMemory_5edc {
  strings:
    $key_5edc = { 09 ae [2] 3b 8c [2] 3d b9 [2] 13 b9 [2] 2c a5 }

  condition:
    any of them
}