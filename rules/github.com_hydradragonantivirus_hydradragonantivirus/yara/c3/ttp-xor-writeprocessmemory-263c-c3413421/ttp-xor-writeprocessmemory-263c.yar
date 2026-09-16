rule TTP_XOR_WriteProcessMemory_263c {
  strings:
    $key_263c = { 71 4e [2] 43 6c [2] 45 59 [2] 6b 59 [2] 54 45 }

  condition:
    any of them
}