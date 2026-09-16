rule TTP_XOR_WriteProcessMemory_0671 {
  strings:
    $key_0671 = { 51 03 [2] 63 21 [2] 65 14 [2] 4b 14 [2] 74 08 }

  condition:
    any of them
}