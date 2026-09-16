rule TTP_XOR_WriteProcessMemory_00e8 {
  strings:
    $key_00e8 = { 57 9a [2] 65 b8 [2] 63 8d [2] 4d 8d [2] 72 91 }

  condition:
    any of them
}