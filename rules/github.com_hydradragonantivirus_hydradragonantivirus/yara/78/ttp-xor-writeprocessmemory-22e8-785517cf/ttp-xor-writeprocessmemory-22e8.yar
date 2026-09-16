rule TTP_XOR_WriteProcessMemory_22e8 {
  strings:
    $key_22e8 = { 75 9a [2] 47 b8 [2] 41 8d [2] 6f 8d [2] 50 91 }

  condition:
    any of them
}