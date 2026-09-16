rule TTP_XOR_WriteProcessMemory_7520 {
  strings:
    $key_7520 = { 22 52 [2] 10 70 [2] 16 45 [2] 38 45 [2] 07 59 }

  condition:
    any of them
}