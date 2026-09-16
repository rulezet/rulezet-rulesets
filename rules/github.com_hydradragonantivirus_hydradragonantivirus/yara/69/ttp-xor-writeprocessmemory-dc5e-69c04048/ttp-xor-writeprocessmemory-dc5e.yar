rule TTP_XOR_WriteProcessMemory_dc5e {
  strings:
    $key_dc5e = { 8b 2c [2] b9 0e [2] bf 3b [2] 91 3b [2] ae 27 }

  condition:
    any of them
}