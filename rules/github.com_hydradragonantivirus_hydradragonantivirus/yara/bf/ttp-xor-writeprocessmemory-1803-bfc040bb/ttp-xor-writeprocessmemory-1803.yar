rule TTP_XOR_WriteProcessMemory_1803 {
  strings:
    $key_1803 = { 4f 71 [2] 7d 53 [2] 7b 66 [2] 55 66 [2] 6a 7a }

  condition:
    any of them
}