rule TTP_XOR_WriteProcessMemory_4eed {
  strings:
    $key_4eed = { 19 9f [2] 2b bd [2] 2d 88 [2] 03 88 [2] 3c 94 }

  condition:
    any of them
}