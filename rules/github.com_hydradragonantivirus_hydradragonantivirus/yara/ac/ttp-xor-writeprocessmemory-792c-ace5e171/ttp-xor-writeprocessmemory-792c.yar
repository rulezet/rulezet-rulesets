rule TTP_XOR_WriteProcessMemory_792c {
  strings:
    $key_792c = { 2e 5e [2] 1c 7c [2] 1a 49 [2] 34 49 [2] 0b 55 }

  condition:
    any of them
}