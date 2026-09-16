rule TTP_XOR_WriteProcessMemory_dd60 {
  strings:
    $key_dd60 = { 8a 12 [2] b8 30 [2] be 05 [2] 90 05 [2] af 19 }

  condition:
    any of them
}