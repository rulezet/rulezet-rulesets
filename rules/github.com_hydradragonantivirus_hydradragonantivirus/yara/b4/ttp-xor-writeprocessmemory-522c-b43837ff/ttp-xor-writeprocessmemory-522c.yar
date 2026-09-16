rule TTP_XOR_WriteProcessMemory_522c {
  strings:
    $key_522c = { 05 5e [2] 37 7c [2] 31 49 [2] 1f 49 [2] 20 55 }

  condition:
    any of them
}