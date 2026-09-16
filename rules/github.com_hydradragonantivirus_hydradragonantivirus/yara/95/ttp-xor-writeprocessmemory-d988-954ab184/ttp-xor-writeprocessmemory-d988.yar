rule TTP_XOR_WriteProcessMemory_d988 {
  strings:
    $key_d988 = { 8e fa [2] bc d8 [2] ba ed [2] 94 ed [2] ab f1 }

  condition:
    any of them
}