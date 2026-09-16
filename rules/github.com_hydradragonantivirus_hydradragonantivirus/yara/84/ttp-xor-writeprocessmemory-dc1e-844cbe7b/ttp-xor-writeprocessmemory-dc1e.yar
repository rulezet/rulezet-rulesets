rule TTP_XOR_WriteProcessMemory_dc1e {
  strings:
    $key_dc1e = { 8b 6c [2] b9 4e [2] bf 7b [2] 91 7b [2] ae 67 }

  condition:
    any of them
}