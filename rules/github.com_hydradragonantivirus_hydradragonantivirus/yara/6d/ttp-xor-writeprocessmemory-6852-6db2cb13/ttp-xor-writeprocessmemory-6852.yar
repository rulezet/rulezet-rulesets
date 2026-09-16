rule TTP_XOR_WriteProcessMemory_6852 {
  strings:
    $key_6852 = { 3f 20 [2] 0d 02 [2] 0b 37 [2] 25 37 [2] 1a 2b }

  condition:
    any of them
}