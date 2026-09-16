rule TTP_XOR_WriteProcessMemory_dc1c {
  strings:
    $key_dc1c = { 8b 6e [2] b9 4c [2] bf 79 [2] 91 79 [2] ae 65 }

  condition:
    any of them
}