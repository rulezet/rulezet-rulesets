rule TTP_XOR_WriteProcessMemory_e328 {
  strings:
    $key_e328 = { b4 5a [2] 86 78 [2] 80 4d [2] ae 4d [2] 91 51 }

  condition:
    any of them
}