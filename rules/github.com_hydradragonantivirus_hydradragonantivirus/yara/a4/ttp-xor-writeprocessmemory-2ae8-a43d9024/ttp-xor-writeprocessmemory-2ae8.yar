rule TTP_XOR_WriteProcessMemory_2ae8 {
  strings:
    $key_2ae8 = { 7d 9a [2] 4f b8 [2] 49 8d [2] 67 8d [2] 58 91 }

  condition:
    any of them
}