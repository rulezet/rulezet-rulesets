rule TTP_XOR_WriteProcessMemory_0fc3 {
  strings:
    $key_0fc3 = { 58 b1 [2] 6a 93 [2] 6c a6 [2] 42 a6 [2] 7d ba }

  condition:
    any of them
}