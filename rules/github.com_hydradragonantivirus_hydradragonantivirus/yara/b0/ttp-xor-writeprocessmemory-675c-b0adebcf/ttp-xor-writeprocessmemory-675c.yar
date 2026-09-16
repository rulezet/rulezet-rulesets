rule TTP_XOR_WriteProcessMemory_675c {
  strings:
    $key_675c = { 30 2e [2] 02 0c [2] 04 39 [2] 2a 39 [2] 15 25 }

  condition:
    any of them
}