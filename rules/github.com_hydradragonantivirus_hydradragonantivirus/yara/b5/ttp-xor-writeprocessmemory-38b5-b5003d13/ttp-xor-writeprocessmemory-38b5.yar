rule TTP_XOR_WriteProcessMemory_38b5 {
  strings:
    $key_38b5 = { 6f c7 [2] 5d e5 [2] 5b d0 [2] 75 d0 [2] 4a cc }

  condition:
    any of them
}