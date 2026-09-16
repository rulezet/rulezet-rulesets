rule TTP_XOR_WriteProcessMemory_54e8 {
  strings:
    $key_54e8 = { 03 9a [2] 31 b8 [2] 37 8d [2] 19 8d [2] 26 91 }

  condition:
    any of them
}