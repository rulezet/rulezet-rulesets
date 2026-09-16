rule TTP_XOR_WriteProcessMemory_08e8 {
  strings:
    $key_08e8 = { 5f 9a [2] 6d b8 [2] 6b 8d [2] 45 8d [2] 7a 91 }

  condition:
    any of them
}