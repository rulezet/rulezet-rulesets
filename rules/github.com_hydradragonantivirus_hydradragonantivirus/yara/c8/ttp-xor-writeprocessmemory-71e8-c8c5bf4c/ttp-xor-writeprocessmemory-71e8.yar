rule TTP_XOR_WriteProcessMemory_71e8 {
  strings:
    $key_71e8 = { 26 9a [2] 14 b8 [2] 12 8d [2] 3c 8d [2] 03 91 }

  condition:
    any of them
}