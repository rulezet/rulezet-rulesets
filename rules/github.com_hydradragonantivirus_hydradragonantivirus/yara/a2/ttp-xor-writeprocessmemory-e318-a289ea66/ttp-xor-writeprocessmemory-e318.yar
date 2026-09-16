rule TTP_XOR_WriteProcessMemory_e318 {
  strings:
    $key_e318 = { b4 6a [2] 86 48 [2] 80 7d [2] ae 7d [2] 91 61 }

  condition:
    any of them
}