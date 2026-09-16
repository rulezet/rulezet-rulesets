rule TTP_XOR_WriteProcessMemory_3428 {
  strings:
    $key_3428 = { 63 5a [2] 51 78 [2] 57 4d [2] 79 4d [2] 46 51 }

  condition:
    any of them
}