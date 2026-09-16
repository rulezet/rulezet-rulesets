rule TTP_XOR_WriteProcessMemory_d896 {
  strings:
    $key_d896 = { 8f e4 [2] bd c6 [2] bb f3 [2] 95 f3 [2] aa ef }

  condition:
    any of them
}