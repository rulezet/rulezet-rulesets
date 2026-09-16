rule TTP_XOR_WriteProcessMemory_28b5 {
  strings:
    $key_28b5 = { 7f c7 [2] 4d e5 [2] 4b d0 [2] 65 d0 [2] 5a cc }

  condition:
    any of them
}