rule TTP_XOR_WriteProcessMemory_48b5 {
  strings:
    $key_48b5 = { 1f c7 [2] 2d e5 [2] 2b d0 [2] 05 d0 [2] 3a cc }

  condition:
    any of them
}