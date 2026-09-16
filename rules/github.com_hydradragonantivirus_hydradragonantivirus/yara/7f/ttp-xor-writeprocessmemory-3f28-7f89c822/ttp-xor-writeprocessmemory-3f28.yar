rule TTP_XOR_WriteProcessMemory_3f28 {
  strings:
    $key_3f28 = { 68 5a [2] 5a 78 [2] 5c 4d [2] 72 4d [2] 4d 51 }

  condition:
    any of them
}