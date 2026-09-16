rule TTP_XOR_WriteProcessMemory_3fed {
  strings:
    $key_3fed = { 68 9f [2] 5a bd [2] 5c 88 [2] 72 88 [2] 4d 94 }

  condition:
    any of them
}