rule TTP_XOR_WriteProcessMemory_5eed {
  strings:
    $key_5eed = { 09 9f [2] 3b bd [2] 3d 88 [2] 13 88 [2] 2c 94 }

  condition:
    any of them
}