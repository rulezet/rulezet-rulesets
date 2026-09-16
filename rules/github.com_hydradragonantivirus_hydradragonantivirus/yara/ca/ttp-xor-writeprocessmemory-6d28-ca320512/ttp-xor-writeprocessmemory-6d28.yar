rule TTP_XOR_WriteProcessMemory_6d28 {
  strings:
    $key_6d28 = { 3a 5a [2] 08 78 [2] 0e 4d [2] 20 4d [2] 1f 51 }

  condition:
    any of them
}