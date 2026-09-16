rule TTP_XOR_WriteProcessMemory_dc4d {
  strings:
    $key_dc4d = { 8b 3f [2] b9 1d [2] bf 28 [2] 91 28 [2] ae 34 }

  condition:
    any of them
}