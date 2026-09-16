rule TTP_XOR_WriteProcessMemory_1888 {
  strings:
    $key_1888 = { 4f fa [2] 7d d8 [2] 7b ed [2] 55 ed [2] 6a f1 }

  condition:
    any of them
}