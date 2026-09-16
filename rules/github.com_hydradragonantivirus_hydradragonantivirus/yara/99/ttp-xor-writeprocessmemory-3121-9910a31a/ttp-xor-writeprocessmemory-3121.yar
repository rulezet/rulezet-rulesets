rule TTP_XOR_WriteProcessMemory_3121 {
  strings:
    $key_3121 = { 66 53 [2] 54 71 [2] 52 44 [2] 7c 44 [2] 43 58 }

  condition:
    any of them
}