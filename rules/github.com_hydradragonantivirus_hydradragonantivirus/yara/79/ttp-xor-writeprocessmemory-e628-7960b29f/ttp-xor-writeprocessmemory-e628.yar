rule TTP_XOR_WriteProcessMemory_e628 {
  strings:
    $key_e628 = { b1 5a [2] 83 78 [2] 85 4d [2] ab 4d [2] 94 51 }

  condition:
    any of them
}