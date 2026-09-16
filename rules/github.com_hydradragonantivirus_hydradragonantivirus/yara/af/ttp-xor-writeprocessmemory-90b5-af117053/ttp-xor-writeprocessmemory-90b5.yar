rule TTP_XOR_WriteProcessMemory_90b5 {
  strings:
    $key_90b5 = { c7 c7 [2] f5 e5 [2] f3 d0 [2] dd d0 [2] e2 cc }

  condition:
    any of them
}