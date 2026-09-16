rule TTP_XOR_WriteProcessMemory_04f8 {
  strings:
    $key_04f8 = { 53 8a [2] 61 a8 [2] 67 9d [2] 49 9d [2] 76 81 }

  condition:
    any of them
}