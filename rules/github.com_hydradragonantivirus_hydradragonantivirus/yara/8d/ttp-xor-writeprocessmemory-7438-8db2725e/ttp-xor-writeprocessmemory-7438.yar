rule TTP_XOR_WriteProcessMemory_7438 {
  strings:
    $key_7438 = { 23 4a [2] 11 68 [2] 17 5d [2] 39 5d [2] 06 41 }

  condition:
    any of them
}