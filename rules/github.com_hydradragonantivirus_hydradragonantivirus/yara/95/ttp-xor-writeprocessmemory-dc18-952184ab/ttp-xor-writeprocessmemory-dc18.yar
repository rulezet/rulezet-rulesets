rule TTP_XOR_WriteProcessMemory_dc18 {
  strings:
    $key_dc18 = { 8b 6a [2] b9 48 [2] bf 7d [2] 91 7d [2] ae 61 }

  condition:
    any of them
}