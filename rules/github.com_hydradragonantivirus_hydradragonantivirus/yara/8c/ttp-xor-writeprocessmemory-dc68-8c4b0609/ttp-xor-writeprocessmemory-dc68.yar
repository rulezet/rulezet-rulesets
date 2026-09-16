rule TTP_XOR_WriteProcessMemory_dc68 {
  strings:
    $key_dc68 = { 8b 1a [2] b9 38 [2] bf 0d [2] 91 0d [2] ae 11 }

  condition:
    any of them
}