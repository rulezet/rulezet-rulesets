rule TTP_XOR_WriteProcessMemory_f8dc {
  strings:
    $key_f8dc = { af ae [2] 9d 8c [2] 9b b9 [2] b5 b9 [2] 8a a5 }

  condition:
    any of them
}