rule TTP_XOR_WriteProcessMemory_2d28 {
  strings:
    $key_2d28 = { 7a 5a [2] 48 78 [2] 4e 4d [2] 60 4d [2] 5f 51 }

  condition:
    any of them
}