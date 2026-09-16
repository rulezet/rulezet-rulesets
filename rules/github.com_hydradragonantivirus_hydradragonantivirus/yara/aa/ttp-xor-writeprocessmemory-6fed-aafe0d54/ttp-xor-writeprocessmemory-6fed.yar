rule TTP_XOR_WriteProcessMemory_6fed {
  strings:
    $key_6fed = { 38 9f [2] 0a bd [2] 0c 88 [2] 22 88 [2] 1d 94 }

  condition:
    any of them
}