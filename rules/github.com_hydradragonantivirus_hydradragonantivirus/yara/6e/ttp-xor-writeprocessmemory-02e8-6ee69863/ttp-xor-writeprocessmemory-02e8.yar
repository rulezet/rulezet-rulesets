rule TTP_XOR_WriteProcessMemory_02e8 {
  strings:
    $key_02e8 = { 55 9a [2] 67 b8 [2] 61 8d [2] 4f 8d [2] 70 91 }

  condition:
    any of them
}