rule TTP_XOR_WriteProcessMemory_dc5b {
  strings:
    $key_dc5b = { 8b 29 [2] b9 0b [2] bf 3e [2] 91 3e [2] ae 22 }

  condition:
    any of them
}