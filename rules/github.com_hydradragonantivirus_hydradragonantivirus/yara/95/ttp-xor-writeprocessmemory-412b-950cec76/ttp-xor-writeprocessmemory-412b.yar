rule TTP_XOR_WriteProcessMemory_412b {
  strings:
    $key_412b = { 16 59 [2] 24 7b [2] 22 4e [2] 0c 4e [2] 33 52 }

  condition:
    any of them
}