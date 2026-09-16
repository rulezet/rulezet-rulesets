rule TTP_XOR_WriteProcessMemory_dd85 {
  strings:
    $key_dd85 = { 8a f7 [2] b8 d5 [2] be e0 [2] 90 e0 [2] af fc }

  condition:
    any of them
}