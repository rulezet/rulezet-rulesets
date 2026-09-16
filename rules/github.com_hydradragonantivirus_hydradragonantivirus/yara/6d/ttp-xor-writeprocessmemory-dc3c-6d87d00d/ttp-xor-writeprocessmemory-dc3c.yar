rule TTP_XOR_WriteProcessMemory_dc3c {
  strings:
    $key_dc3c = { 8b 4e [2] b9 6c [2] bf 59 [2] 91 59 [2] ae 45 }

  condition:
    any of them
}