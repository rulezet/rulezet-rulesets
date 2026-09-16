rule TTP_XOR_WriteProcessMemory_6eed {
  strings:
    $key_6eed = { 39 9f [2] 0b bd [2] 0d 88 [2] 23 88 [2] 1c 94 }

  condition:
    any of them
}