rule TTP_XOR_WriteProcessMemory_3628 {
  strings:
    $key_3628 = { 61 5a [2] 53 78 [2] 55 4d [2] 7b 4d [2] 44 51 }

  condition:
    any of them
}