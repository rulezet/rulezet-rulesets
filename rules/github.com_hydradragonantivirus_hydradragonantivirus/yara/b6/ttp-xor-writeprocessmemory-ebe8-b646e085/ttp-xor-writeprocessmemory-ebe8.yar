rule TTP_XOR_WriteProcessMemory_ebe8 {
  strings:
    $key_ebe8 = { bc 9a [2] 8e b8 [2] 88 8d [2] a6 8d [2] 99 91 }

  condition:
    any of them
}