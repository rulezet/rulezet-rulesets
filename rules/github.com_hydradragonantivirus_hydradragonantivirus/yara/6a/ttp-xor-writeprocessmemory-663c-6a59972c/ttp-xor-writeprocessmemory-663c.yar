rule TTP_XOR_WriteProcessMemory_663c {
  strings:
    $key_663c = { 31 4e [2] 03 6c [2] 05 59 [2] 2b 59 [2] 14 45 }

  condition:
    any of them
}