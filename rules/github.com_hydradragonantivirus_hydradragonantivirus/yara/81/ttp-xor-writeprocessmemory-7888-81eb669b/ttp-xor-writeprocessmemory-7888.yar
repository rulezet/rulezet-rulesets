rule TTP_XOR_WriteProcessMemory_7888 {
  strings:
    $key_7888 = { 2f fa [2] 1d d8 [2] 1b ed [2] 35 ed [2] 0a f1 }

  condition:
    any of them
}