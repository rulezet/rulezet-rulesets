rule TTP_XOR_WriteProcessMemory_103c {
  strings:
    $key_103c = { 47 4e [2] 75 6c [2] 73 59 [2] 5d 59 [2] 62 45 }

  condition:
    any of them
}