rule TTP_XOR_WriteProcessMemory_683c {
  strings:
    $key_683c = { 3f 4e [2] 0d 6c [2] 0b 59 [2] 25 59 [2] 1a 45 }

  condition:
    any of them
}