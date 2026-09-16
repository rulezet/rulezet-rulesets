rule TTP_XOR_WriteProcessMemory_610d {
  strings:
    $key_610d = { 36 7f [2] 04 5d [2] 02 68 [2] 2c 68 [2] 13 74 }

  condition:
    any of them
}