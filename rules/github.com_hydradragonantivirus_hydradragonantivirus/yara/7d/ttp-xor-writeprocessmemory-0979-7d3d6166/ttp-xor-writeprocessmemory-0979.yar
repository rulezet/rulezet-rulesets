rule TTP_XOR_WriteProcessMemory_0979 {
  strings:
    $key_0979 = { 5e 0b [2] 6c 29 [2] 6a 1c [2] 44 1c [2] 7b 00 }

  condition:
    any of them
}