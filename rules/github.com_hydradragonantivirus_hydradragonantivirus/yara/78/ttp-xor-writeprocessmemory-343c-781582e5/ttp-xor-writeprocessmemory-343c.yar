rule TTP_XOR_WriteProcessMemory_343c {
  strings:
    $key_343c = { 63 4e [2] 51 6c [2] 57 59 [2] 79 59 [2] 46 45 }

  condition:
    any of them
}