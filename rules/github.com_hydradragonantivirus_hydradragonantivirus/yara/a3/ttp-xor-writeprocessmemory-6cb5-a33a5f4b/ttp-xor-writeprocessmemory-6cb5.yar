rule TTP_XOR_WriteProcessMemory_6cb5 {
  strings:
    $key_6cb5 = { 3b c7 [2] 09 e5 [2] 0f d0 [2] 21 d0 [2] 1e cc }

  condition:
    any of them
}