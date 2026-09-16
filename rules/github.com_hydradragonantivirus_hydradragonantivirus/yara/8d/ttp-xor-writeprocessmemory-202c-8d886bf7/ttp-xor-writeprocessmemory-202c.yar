rule TTP_XOR_WriteProcessMemory_202c {
  strings:
    $key_202c = { 77 5e [2] 45 7c [2] 43 49 [2] 6d 49 [2] 52 55 }

  condition:
    any of them
}