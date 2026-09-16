rule TTP_XOR_WriteProcessMemory_dd54 {
  strings:
    $key_dd54 = { 8a 26 [2] b8 04 [2] be 31 [2] 90 31 [2] af 2d }

  condition:
    any of them
}