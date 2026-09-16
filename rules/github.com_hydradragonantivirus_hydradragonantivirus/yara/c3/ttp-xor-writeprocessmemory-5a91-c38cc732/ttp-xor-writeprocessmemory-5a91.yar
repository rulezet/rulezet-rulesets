rule TTP_XOR_WriteProcessMemory_5a91 {
  strings:
    $key_5a91 = { 0d e3 [2] 3f c1 [2] 39 f4 [2] 17 f4 [2] 28 e8 }

  condition:
    any of them
}