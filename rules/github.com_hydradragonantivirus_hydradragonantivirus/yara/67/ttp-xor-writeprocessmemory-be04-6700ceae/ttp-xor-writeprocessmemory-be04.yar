rule TTP_XOR_WriteProcessMemory_be04 {
  strings:
    $key_be04 = { e9 76 [2] db 54 [2] dd 61 [2] f3 61 [2] cc 7d }

  condition:
    any of them
}