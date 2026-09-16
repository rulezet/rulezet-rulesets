rule TTP_XOR_WriteProcessMemory_05b5 {
  strings:
    $key_05b5 = { 52 c7 [2] 60 e5 [2] 66 d0 [2] 48 d0 [2] 77 cc }

  condition:
    any of them
}