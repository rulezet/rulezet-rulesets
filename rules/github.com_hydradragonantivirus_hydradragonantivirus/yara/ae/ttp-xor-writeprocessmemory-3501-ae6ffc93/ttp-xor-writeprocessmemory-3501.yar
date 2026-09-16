rule TTP_XOR_WriteProcessMemory_3501 {
  strings:
    $key_3501 = { 62 73 [2] 50 51 [2] 56 64 [2] 78 64 [2] 47 78 }

  condition:
    any of them
}