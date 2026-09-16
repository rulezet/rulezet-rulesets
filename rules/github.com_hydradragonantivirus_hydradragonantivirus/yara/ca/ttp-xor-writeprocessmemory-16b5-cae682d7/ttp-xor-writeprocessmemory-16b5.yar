rule TTP_XOR_WriteProcessMemory_16b5 {
  strings:
    $key_16b5 = { 41 c7 [2] 73 e5 [2] 75 d0 [2] 5b d0 [2] 64 cc }

  condition:
    any of them
}