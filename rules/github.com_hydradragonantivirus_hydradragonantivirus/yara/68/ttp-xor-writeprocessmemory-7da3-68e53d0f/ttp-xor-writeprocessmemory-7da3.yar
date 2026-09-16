rule TTP_XOR_WriteProcessMemory_7da3 {
  strings:
    $key_7da3 = { 2a d1 [2] 18 f3 [2] 1e c6 [2] 30 c6 [2] 0f da }

  condition:
    any of them
}