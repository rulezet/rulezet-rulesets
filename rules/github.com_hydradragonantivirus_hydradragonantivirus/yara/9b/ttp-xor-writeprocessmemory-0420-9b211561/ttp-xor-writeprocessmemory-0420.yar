rule TTP_XOR_WriteProcessMemory_0420 {
  strings:
    $key_0420 = { 53 52 [2] 61 70 [2] 67 45 [2] 49 45 [2] 76 59 }

  condition:
    any of them
}