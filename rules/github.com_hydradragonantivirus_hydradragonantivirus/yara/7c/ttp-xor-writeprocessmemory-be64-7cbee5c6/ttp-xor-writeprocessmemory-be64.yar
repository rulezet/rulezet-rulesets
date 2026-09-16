rule TTP_XOR_WriteProcessMemory_be64 {
  strings:
    $key_be64 = { e9 16 [2] db 34 [2] dd 01 [2] f3 01 [2] cc 1d }

  condition:
    any of them
}