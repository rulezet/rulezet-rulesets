rule TTP_XOR_WriteProcessMemory_0eed {
  strings:
    $key_0eed = { 59 9f [2] 6b bd [2] 6d 88 [2] 43 88 [2] 7c 94 }

  condition:
    any of them
}