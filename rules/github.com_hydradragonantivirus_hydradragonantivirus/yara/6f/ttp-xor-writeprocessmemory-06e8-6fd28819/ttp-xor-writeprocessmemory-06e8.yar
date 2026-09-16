rule TTP_XOR_WriteProcessMemory_06e8 {
  strings:
    $key_06e8 = { 51 9a [2] 63 b8 [2] 65 8d [2] 4b 8d [2] 74 91 }

  condition:
    any of them
}