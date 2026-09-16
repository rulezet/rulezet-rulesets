rule TTP_XOR_WriteProcessMemory_646e {
  strings:
    $key_646e = { 33 1c [2] 01 3e [2] 07 0b [2] 29 0b [2] 16 17 }

  condition:
    any of them
}