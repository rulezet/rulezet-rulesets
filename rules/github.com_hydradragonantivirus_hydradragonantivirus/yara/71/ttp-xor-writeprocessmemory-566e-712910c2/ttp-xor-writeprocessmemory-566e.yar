rule TTP_XOR_WriteProcessMemory_566e {
  strings:
    $key_566e = { 01 1c [2] 33 3e [2] 35 0b [2] 1b 0b [2] 24 17 }

  condition:
    any of them
}