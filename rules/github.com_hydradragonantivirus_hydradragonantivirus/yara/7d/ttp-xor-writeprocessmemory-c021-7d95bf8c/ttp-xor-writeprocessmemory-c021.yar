rule TTP_XOR_WriteProcessMemory_c021 {
  strings:
    $key_c021 = { 97 53 [2] a5 71 [2] a3 44 [2] 8d 44 [2] b2 58 }

  condition:
    any of them
}