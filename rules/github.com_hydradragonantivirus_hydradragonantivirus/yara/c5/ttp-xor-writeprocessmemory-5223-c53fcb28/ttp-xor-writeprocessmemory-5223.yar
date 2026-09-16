rule TTP_XOR_WriteProcessMemory_5223 {
  strings:
    $key_5223 = { 05 51 [2] 37 73 [2] 31 46 [2] 1f 46 [2] 20 5a }

  condition:
    any of them
}