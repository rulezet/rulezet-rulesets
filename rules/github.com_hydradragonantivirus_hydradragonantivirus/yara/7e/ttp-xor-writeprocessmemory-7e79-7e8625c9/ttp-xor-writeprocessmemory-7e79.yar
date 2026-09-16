rule TTP_XOR_WriteProcessMemory_7e79 {
  strings:
    $key_7e79 = { 29 0b [2] 1b 29 [2] 1d 1c [2] 33 1c [2] 0c 00 }

  condition:
    any of them
}