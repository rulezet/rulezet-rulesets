rule TTP_XOR_WriteProcessMemory_dc48 {
  strings:
    $key_dc48 = { 8b 3a [2] b9 18 [2] bf 2d [2] 91 2d [2] ae 31 }

  condition:
    any of them
}