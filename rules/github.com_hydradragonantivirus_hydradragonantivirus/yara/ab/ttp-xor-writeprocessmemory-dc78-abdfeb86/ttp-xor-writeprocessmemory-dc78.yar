rule TTP_XOR_WriteProcessMemory_dc78 {
  strings:
    $key_dc78 = { 8b 0a [2] b9 28 [2] bf 1d [2] 91 1d [2] ae 01 }

  condition:
    any of them
}