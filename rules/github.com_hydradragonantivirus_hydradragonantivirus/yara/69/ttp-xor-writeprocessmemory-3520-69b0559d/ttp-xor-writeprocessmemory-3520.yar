rule TTP_XOR_WriteProcessMemory_3520 {
  strings:
    $key_3520 = { 62 52 [2] 50 70 [2] 56 45 [2] 78 45 [2] 47 59 }

  condition:
    any of them
}