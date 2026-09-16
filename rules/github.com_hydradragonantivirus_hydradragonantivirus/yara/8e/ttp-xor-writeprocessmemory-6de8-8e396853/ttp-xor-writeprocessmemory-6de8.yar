rule TTP_XOR_WriteProcessMemory_6de8 {
  strings:
    $key_6de8 = { 3a 9a [2] 08 b8 [2] 0e 8d [2] 20 8d [2] 1f 91 }

  condition:
    any of them
}