rule TTP_XOR_WriteProcessMemory_2ac8 {
  strings:
    $key_2ac8 = { 7d ba [2] 4f 98 [2] 49 ad [2] 67 ad [2] 58 b1 }

  condition:
    any of them
}