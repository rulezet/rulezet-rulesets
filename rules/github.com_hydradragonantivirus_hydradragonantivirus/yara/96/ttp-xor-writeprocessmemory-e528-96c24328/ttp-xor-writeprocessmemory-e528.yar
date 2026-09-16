rule TTP_XOR_WriteProcessMemory_e528 {
  strings:
    $key_e528 = { b2 5a [2] 80 78 [2] 86 4d [2] a8 4d [2] 97 51 }

  condition:
    any of them
}