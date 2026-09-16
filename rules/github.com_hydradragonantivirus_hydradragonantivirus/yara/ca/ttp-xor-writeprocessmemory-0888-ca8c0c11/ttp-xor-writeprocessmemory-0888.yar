rule TTP_XOR_WriteProcessMemory_0888 {
  strings:
    $key_0888 = { 5f fa [2] 6d d8 [2] 6b ed [2] 45 ed [2] 7a f1 }

  condition:
    any of them
}