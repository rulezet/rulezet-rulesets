rule TTP_XOR_WriteProcessMemory_dadc {
  strings:
    $key_dadc = { 8d ae [2] bf 8c [2] b9 b9 [2] 97 b9 [2] a8 a5 }

  condition:
    any of them
}