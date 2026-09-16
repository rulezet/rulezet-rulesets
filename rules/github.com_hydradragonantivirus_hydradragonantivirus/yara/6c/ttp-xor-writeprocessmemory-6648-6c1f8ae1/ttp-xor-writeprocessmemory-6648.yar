rule TTP_XOR_WriteProcessMemory_6648 {
  strings:
    $key_6648 = { 31 3a [2] 03 18 [2] 05 2d [2] 2b 2d [2] 14 31 }

  condition:
    any of them
}