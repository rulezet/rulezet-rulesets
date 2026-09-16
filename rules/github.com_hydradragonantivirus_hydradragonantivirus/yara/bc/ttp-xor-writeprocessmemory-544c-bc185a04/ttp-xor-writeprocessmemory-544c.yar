rule TTP_XOR_WriteProcessMemory_544c {
  strings:
    $key_544c = { 03 3e [2] 31 1c [2] 37 29 [2] 19 29 [2] 26 35 }

  condition:
    any of them
}