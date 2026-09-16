rule TTP_XOR_WriteProcessMemory_584c {
  strings:
    $key_584c = { 0f 3e [2] 3d 1c [2] 3b 29 [2] 15 29 [2] 2a 35 }

  condition:
    any of them
}