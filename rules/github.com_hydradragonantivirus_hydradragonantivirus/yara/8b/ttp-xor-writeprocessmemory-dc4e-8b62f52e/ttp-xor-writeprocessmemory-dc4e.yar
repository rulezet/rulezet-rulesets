rule TTP_XOR_WriteProcessMemory_dc4e {
  strings:
    $key_dc4e = { 8b 3c [2] b9 1e [2] bf 2b [2] 91 2b [2] ae 37 }

  condition:
    any of them
}