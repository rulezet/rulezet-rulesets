rule TTP_XOR_WriteProcessMemory_3028 {
  strings:
    $key_3028 = { 67 5a [2] 55 78 [2] 53 4d [2] 7d 4d [2] 42 51 }

  condition:
    any of them
}