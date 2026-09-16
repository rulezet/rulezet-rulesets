rule TTP_XOR_WriteProcessMemory_664e {
  strings:
    $key_664e = { 31 3c [2] 03 1e [2] 05 2b [2] 2b 2b [2] 14 37 }

  condition:
    any of them
}