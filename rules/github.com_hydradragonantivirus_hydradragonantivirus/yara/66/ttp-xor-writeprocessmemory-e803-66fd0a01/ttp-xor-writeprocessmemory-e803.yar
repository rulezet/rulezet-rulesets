rule TTP_XOR_WriteProcessMemory_e803 {
  strings:
    $key_e803 = { bf 71 [2] 8d 53 [2] 8b 66 [2] a5 66 [2] 9a 7a }

  condition:
    any of them
}