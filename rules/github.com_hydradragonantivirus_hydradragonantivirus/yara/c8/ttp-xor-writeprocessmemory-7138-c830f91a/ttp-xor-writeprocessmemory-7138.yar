rule TTP_XOR_WriteProcessMemory_7138 {
  strings:
    $key_7138 = { 26 4a [2] 14 68 [2] 12 5d [2] 3c 5d [2] 03 41 }

  condition:
    any of them
}