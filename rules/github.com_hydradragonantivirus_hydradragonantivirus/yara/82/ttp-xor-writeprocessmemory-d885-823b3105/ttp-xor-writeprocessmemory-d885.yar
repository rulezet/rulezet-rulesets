rule TTP_XOR_WriteProcessMemory_d885 {
  strings:
    $key_d885 = { 8f f7 [2] bd d5 [2] bb e0 [2] 95 e0 [2] aa fc }

  condition:
    any of them
}