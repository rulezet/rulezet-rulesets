rule TTP_XOR_WriteProcessMemory_dc7b {
  strings:
    $key_dc7b = { 8b 09 [2] b9 2b [2] bf 1e [2] 91 1e [2] ae 02 }

  condition:
    any of them
}