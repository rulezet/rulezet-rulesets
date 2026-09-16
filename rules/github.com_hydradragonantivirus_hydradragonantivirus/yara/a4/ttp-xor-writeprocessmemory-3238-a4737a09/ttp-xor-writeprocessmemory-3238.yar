rule TTP_XOR_WriteProcessMemory_3238 {
  strings:
    $key_3238 = { 65 4a [2] 57 68 [2] 51 5d [2] 7f 5d [2] 40 41 }

  condition:
    any of them
}