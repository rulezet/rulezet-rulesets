rule TTP_XOR_WriteProcessMemory_5fed {
  strings:
    $key_5fed = { 08 9f [2] 3a bd [2] 3c 88 [2] 12 88 [2] 2d 94 }

  condition:
    any of them
}