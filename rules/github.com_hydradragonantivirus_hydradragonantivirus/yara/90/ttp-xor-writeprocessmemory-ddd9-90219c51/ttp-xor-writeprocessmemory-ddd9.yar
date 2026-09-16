rule TTP_XOR_WriteProcessMemory_ddd9 {
  strings:
    $key_ddd9 = { 8a ab [2] b8 89 [2] be bc [2] 90 bc [2] af a0 }

  condition:
    any of them
}