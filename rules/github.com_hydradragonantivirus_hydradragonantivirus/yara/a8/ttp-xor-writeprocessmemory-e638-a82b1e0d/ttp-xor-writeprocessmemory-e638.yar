rule TTP_XOR_WriteProcessMemory_e638 {
  strings:
    $key_e638 = { b1 4a [2] 83 68 [2] 85 5d [2] ab 5d [2] 94 41 }

  condition:
    any of them
}