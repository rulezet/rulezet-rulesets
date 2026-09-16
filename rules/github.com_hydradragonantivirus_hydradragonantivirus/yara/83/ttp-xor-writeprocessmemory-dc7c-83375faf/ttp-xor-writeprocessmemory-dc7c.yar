rule TTP_XOR_WriteProcessMemory_dc7c {
  strings:
    $key_dc7c = { 8b 0e [2] b9 2c [2] bf 19 [2] 91 19 [2] ae 05 }

  condition:
    any of them
}