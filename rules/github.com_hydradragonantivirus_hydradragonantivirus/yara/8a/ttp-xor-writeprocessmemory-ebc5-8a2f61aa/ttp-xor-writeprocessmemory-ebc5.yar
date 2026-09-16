rule TTP_XOR_WriteProcessMemory_ebc5 {
  strings:
    $key_ebc5 = { bc b7 [2] 8e 95 [2] 88 a0 [2] a6 a0 [2] 99 bc }

  condition:
    any of them
}