rule TTP_XOR_WriteProcessMemory_4852 {
  strings:
    $key_4852 = { 1f 20 [2] 2d 02 [2] 2b 37 [2] 05 37 [2] 3a 2b }

  condition:
    any of them
}