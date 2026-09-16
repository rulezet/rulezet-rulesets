rule TTP_XOR_WriteProcessMemory_00b5 {
  strings:
    $key_00b5 = { 57 c7 [2] 65 e5 [2] 63 d0 [2] 4d d0 [2] 72 cc }

  condition:
    any of them
}