rule TTP_XOR_WriteProcessMemory_26b5 {
  strings:
    $key_26b5 = { 71 c7 [2] 43 e5 [2] 45 d0 [2] 6b d0 [2] 54 cc }

  condition:
    any of them
}