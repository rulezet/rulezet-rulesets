rule TTP_XOR_WriteProcessMemory_dd24 {
  strings:
    $key_dd24 = { 8a 56 [2] b8 74 [2] be 41 [2] 90 41 [2] af 5d }

  condition:
    any of them
}