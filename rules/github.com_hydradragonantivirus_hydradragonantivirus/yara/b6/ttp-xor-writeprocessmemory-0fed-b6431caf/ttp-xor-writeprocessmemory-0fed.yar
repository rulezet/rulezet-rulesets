rule TTP_XOR_WriteProcessMemory_0fed {
  strings:
    $key_0fed = { 58 9f [2] 6a bd [2] 6c 88 [2] 42 88 [2] 7d 94 }

  condition:
    any of them
}