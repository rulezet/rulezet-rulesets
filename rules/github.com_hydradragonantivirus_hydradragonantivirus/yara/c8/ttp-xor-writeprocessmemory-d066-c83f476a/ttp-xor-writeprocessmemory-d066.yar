rule TTP_XOR_WriteProcessMemory_d066 {
  strings:
    $key_d066 = { 87 14 [2] b5 36 [2] b3 03 [2] 9d 03 [2] a2 1f }

  condition:
    any of them
}