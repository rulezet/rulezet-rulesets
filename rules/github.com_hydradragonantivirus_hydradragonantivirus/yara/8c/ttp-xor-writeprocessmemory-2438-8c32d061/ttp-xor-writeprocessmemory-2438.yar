rule TTP_XOR_WriteProcessMemory_2438 {
  strings:
    $key_2438 = { 73 4a [2] 41 68 [2] 47 5d [2] 69 5d [2] 56 41 }

  condition:
    any of them
}