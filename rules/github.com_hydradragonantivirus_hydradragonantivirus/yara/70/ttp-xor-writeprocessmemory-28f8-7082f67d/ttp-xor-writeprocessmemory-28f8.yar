rule TTP_XOR_WriteProcessMemory_28f8 {
  strings:
    $key_28f8 = { 7f 8a [2] 4d a8 [2] 4b 9d [2] 65 9d [2] 5a 81 }

  condition:
    any of them
}