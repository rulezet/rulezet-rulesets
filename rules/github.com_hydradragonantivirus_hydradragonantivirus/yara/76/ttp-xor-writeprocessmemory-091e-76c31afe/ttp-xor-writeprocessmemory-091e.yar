rule TTP_XOR_WriteProcessMemory_091e {
  strings:
    $key_091e = { 5e 6c [2] 6c 4e [2] 6a 7b [2] 44 7b [2] 7b 67 }

  condition:
    any of them
}