rule TTP_XOR_WriteProcessMemory_e701 {
  strings:
    $key_e701 = { b0 73 [2] 82 51 [2] 84 64 [2] aa 64 [2] 95 78 }

  condition:
    any of them
}