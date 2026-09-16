rule TTP_XOR_WriteProcessMemory_3c11 {
  strings:
    $key_3c11 = { 6b 63 [2] 59 41 [2] 5f 74 [2] 71 74 [2] 4e 68 }

  condition:
    any of them
}