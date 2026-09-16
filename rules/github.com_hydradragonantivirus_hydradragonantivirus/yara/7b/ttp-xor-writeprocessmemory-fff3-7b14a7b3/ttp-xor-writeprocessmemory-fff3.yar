rule TTP_XOR_WriteProcessMemory_fff3 {
  strings:
    $key_fff3 = { a8 81 [2] 9a a3 [2] 9c 96 [2] b2 96 [2] 8d 8a }

  condition:
    any of them
}