rule TTP_XOR_WriteProcessMemory_6628 {
  strings:
    $key_6628 = { 31 5a [2] 03 78 [2] 05 4d [2] 2b 4d [2] 14 51 }

  condition:
    any of them
}