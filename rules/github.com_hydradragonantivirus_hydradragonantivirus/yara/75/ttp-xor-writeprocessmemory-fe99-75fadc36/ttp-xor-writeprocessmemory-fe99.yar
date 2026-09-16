rule TTP_XOR_WriteProcessMemory_fe99 {
  strings:
    $key_fe99 = { a9 eb [2] 9b c9 [2] 9d fc [2] b3 fc [2] 8c e0 }

  condition:
    any of them
}