rule TTP_XOR_WriteProcessMemory_3de8 {
  strings:
    $key_3de8 = { 6a 9a [2] 58 b8 [2] 5e 8d [2] 70 8d [2] 4f 91 }

  condition:
    any of them
}