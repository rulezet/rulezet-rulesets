rule TTP_XOR_WriteProcessMemory_dd31 {
  strings:
    $key_dd31 = { 8a 43 [2] b8 61 [2] be 54 [2] 90 54 [2] af 48 }

  condition:
    any of them
}