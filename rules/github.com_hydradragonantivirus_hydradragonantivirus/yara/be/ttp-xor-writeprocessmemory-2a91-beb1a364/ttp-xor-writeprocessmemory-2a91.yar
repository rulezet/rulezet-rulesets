rule TTP_XOR_WriteProcessMemory_2a91 {
  strings:
    $key_2a91 = { 7d e3 [2] 4f c1 [2] 49 f4 [2] 67 f4 [2] 58 e8 }

  condition:
    any of them
}