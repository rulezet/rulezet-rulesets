rule TTP_XOR_WriteProcessMemory_081d {
  strings:
    $key_081d = { 5f 6f [2] 6d 4d [2] 6b 78 [2] 45 78 [2] 7a 64 }

  condition:
    any of them
}