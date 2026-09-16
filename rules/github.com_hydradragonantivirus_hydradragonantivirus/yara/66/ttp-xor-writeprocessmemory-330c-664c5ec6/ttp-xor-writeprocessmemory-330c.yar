rule TTP_XOR_WriteProcessMemory_330c {
  strings:
    $key_330c = { 64 7e [2] 56 5c [2] 50 69 [2] 7e 69 [2] 41 75 }

  condition:
    any of them
}