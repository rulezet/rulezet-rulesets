rule TTP_XOR_WriteProcessMemory_6979 {
  strings:
    $key_6979 = { 3e 0b [2] 0c 29 [2] 0a 1c [2] 24 1c [2] 1b 00 }

  condition:
    any of them
}