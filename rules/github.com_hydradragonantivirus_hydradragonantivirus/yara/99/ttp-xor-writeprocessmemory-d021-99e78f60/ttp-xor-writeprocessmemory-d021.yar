rule TTP_XOR_WriteProcessMemory_d021 {
  strings:
    $key_d021 = { 87 53 [2] b5 71 [2] b3 44 [2] 9d 44 [2] a2 58 }

  condition:
    any of them
}