rule TTP_XOR_WriteProcessMemory_dc2d {
  strings:
    $key_dc2d = { 8b 5f [2] b9 7d [2] bf 48 [2] 91 48 [2] ae 54 }

  condition:
    any of them
}