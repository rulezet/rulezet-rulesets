rule TTP_XOR_WriteProcessMemory_e3dc {
  strings:
    $key_e3dc = { b4 ae [2] 86 8c [2] 80 b9 [2] ae b9 [2] 91 a5 }

  condition:
    any of them
}