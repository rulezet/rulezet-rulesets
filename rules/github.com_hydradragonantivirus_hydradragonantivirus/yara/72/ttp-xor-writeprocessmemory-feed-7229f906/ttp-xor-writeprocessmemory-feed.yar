rule TTP_XOR_WriteProcessMemory_feed {
  strings:
    $key_feed = { a9 9f [2] 9b bd [2] 9d 88 [2] b3 88 [2] 8c 94 }

  condition:
    any of them
}