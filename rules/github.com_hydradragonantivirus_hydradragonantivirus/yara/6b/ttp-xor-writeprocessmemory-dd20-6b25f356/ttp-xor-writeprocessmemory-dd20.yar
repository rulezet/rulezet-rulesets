rule TTP_XOR_WriteProcessMemory_dd20 {
  strings:
    $key_dd20 = { 8a 52 [2] b8 70 [2] be 45 [2] 90 45 [2] af 59 }

  condition:
    any of them
}