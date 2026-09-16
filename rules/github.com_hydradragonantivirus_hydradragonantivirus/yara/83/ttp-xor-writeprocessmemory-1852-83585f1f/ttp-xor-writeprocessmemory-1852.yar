rule TTP_XOR_WriteProcessMemory_1852 {
  strings:
    $key_1852 = { 4f 20 [2] 7d 02 [2] 7b 37 [2] 55 37 [2] 6a 2b }

  condition:
    any of them
}