rule TTP_XOR_WriteProcessMemory_352c {
  strings:
    $key_352c = { 62 5e [2] 50 7c [2] 56 49 [2] 78 49 [2] 47 55 }

  condition:
    any of them
}