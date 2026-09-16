rule TTP_XOR_WriteProcessMemory_624d {
  strings:
    $key_624d = { 35 3f [2] 07 1d [2] 01 28 [2] 2f 28 [2] 10 34 }

  condition:
    any of them
}