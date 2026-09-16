rule TTP_XOR_WriteProcessMemory_624c {
  strings:
    $key_624c = { 35 3e [2] 07 1c [2] 01 29 [2] 2f 29 [2] 10 35 }

  condition:
    any of them
}