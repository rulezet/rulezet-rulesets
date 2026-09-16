rule TTP_XOR_WriteProcessMemory_032c {
  strings:
    $key_032c = { 54 5e [2] 66 7c [2] 60 49 [2] 4e 49 [2] 71 55 }

  condition:
    any of them
}