rule TTP_XOR_WriteProcessMemory_05f8 {
  strings:
    $key_05f8 = { 52 8a [2] 60 a8 [2] 66 9d [2] 48 9d [2] 77 81 }

  condition:
    any of them
}