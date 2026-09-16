rule TTP_XOR_WriteProcessMemory_dc3e {
  strings:
    $key_dc3e = { 8b 4c [2] b9 6e [2] bf 5b [2] 91 5b [2] ae 47 }

  condition:
    any of them
}