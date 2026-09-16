rule TTP_XOR_WriteProcessMemory_104c {
  strings:
    $key_104c = { 47 3e [2] 75 1c [2] 73 29 [2] 5d 29 [2] 62 35 }

  condition:
    any of them
}