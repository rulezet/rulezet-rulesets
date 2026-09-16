rule TTP_XOR_WriteProcessMemory_fe04 {
  strings:
    $key_fe04 = { a9 76 [2] 9b 54 [2] 9d 61 [2] b3 61 [2] 8c 7d }

  condition:
    any of them
}