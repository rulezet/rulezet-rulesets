rule TTP_XOR_WriteProcessMemory_8a91 {
  strings:
    $key_8a91 = { dd e3 [2] ef c1 [2] e9 f4 [2] c7 f4 [2] f8 e8 }

  condition:
    any of them
}