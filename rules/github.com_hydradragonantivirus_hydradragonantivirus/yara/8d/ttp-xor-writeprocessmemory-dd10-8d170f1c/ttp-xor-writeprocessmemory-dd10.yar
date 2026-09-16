rule TTP_XOR_WriteProcessMemory_dd10 {
  strings:
    $key_dd10 = { 8a 62 [2] b8 40 [2] be 75 [2] 90 75 [2] af 69 }

  condition:
    any of them
}