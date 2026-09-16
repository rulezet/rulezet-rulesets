rule TTP_XOR_WriteProcessMemory_dd11 {
  strings:
    $key_dd11 = { 8a 63 [2] b8 41 [2] be 74 [2] 90 74 [2] af 68 }

  condition:
    any of them
}