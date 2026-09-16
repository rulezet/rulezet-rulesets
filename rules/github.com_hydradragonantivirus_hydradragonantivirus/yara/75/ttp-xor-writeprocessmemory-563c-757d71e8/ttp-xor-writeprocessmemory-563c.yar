rule TTP_XOR_WriteProcessMemory_563c {
  strings:
    $key_563c = { 01 4e [2] 33 6c [2] 35 59 [2] 1b 59 [2] 24 45 }

  condition:
    any of them
}