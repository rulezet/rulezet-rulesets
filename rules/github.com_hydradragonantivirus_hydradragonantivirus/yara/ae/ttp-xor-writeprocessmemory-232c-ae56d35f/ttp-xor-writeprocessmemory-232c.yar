rule TTP_XOR_WriteProcessMemory_232c {
  strings:
    $key_232c = { 74 5e [2] 46 7c [2] 40 49 [2] 6e 49 [2] 51 55 }

  condition:
    any of them
}