rule TTP_XOR_WriteProcessMemory_66e8 {
  strings:
    $key_66e8 = { 31 9a [2] 03 b8 [2] 05 8d [2] 2b 8d [2] 14 91 }

  condition:
    any of them
}