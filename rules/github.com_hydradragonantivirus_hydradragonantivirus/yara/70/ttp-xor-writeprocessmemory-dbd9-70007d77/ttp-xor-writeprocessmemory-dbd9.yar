rule TTP_XOR_WriteProcessMemory_dbd9 {
  strings:
    $key_dbd9 = { 8c ab [2] be 89 [2] b8 bc [2] 96 bc [2] a9 a0 }

  condition:
    any of them
}