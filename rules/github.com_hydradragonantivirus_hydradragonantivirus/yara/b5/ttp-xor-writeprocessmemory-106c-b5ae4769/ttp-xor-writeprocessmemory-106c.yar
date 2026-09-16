rule TTP_XOR_WriteProcessMemory_106c {
  strings:
    $key_106c = { 47 1e [2] 75 3c [2] 73 09 [2] 5d 09 [2] 62 15 }

  condition:
    any of them
}