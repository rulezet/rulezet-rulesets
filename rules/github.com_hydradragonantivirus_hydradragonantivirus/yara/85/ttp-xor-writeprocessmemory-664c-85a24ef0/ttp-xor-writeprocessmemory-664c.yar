rule TTP_XOR_WriteProcessMemory_664c {
  strings:
    $key_664c = { 31 3e [2] 03 1c [2] 05 29 [2] 2b 29 [2] 14 35 }

  condition:
    any of them
}