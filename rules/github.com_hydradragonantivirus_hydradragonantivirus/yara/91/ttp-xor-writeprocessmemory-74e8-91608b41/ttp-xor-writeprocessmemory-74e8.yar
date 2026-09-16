rule TTP_XOR_WriteProcessMemory_74e8 {
  strings:
    $key_74e8 = { 23 9a [2] 11 b8 [2] 17 8d [2] 39 8d [2] 06 91 }

  condition:
    any of them
}