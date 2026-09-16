rule TTP_XOR_WriteProcessMemory_3e79 {
  strings:
    $key_3e79 = { 69 0b [2] 5b 29 [2] 5d 1c [2] 73 1c [2] 4c 00 }

  condition:
    any of them
}