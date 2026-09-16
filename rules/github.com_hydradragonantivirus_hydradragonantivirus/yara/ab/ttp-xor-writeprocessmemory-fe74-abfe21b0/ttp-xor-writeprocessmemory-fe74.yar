rule TTP_XOR_WriteProcessMemory_fe74 {
  strings:
    $key_fe74 = { a9 06 [2] 9b 24 [2] 9d 11 [2] b3 11 [2] 8c 0d }

  condition:
    any of them
}