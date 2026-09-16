rule TTP_XOR_WriteProcessMemory_486e {
  strings:
    $key_486e = { 1f 1c [2] 2d 3e [2] 2b 0b [2] 05 0b [2] 3a 17 }

  condition:
    any of them
}