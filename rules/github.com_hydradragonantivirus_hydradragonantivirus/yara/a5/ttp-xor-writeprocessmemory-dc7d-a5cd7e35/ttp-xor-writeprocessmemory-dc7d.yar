rule TTP_XOR_WriteProcessMemory_dc7d {
  strings:
    $key_dc7d = { 8b 0f [2] b9 2d [2] bf 18 [2] 91 18 [2] ae 04 }

  condition:
    any of them
}