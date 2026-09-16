rule TTP_XOR_WriteProcessMemory_e378 {
  strings:
    $key_e378 = { b4 0a [2] 86 28 [2] 80 1d [2] ae 1d [2] 91 01 }

  condition:
    any of them
}