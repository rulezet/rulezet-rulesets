rule TTP_XOR_WriteProcessMemory_0a91 {
  strings:
    $key_0a91 = { 5d e3 [2] 6f c1 [2] 69 f4 [2] 47 f4 [2] 78 e8 }

  condition:
    any of them
}