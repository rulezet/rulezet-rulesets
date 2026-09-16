rule TTP_XOR_WriteProcessMemory_662d {
  strings:
    $key_662d = { 31 5f [2] 03 7d [2] 05 48 [2] 2b 48 [2] 14 54 }

  condition:
    any of them
}