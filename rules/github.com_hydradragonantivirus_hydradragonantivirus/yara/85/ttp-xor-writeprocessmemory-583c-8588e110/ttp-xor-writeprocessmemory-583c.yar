rule TTP_XOR_WriteProcessMemory_583c {
  strings:
    $key_583c = { 0f 4e [2] 3d 6c [2] 3b 59 [2] 15 59 [2] 2a 45 }

  condition:
    any of them
}