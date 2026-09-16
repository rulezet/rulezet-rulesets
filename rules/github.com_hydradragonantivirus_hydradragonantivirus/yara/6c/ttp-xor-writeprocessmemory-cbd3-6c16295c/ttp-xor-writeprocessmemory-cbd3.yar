rule TTP_XOR_WriteProcessMemory_cbd3 {
  strings:
    $key_cbd3 = { 9c a1 [2] ae 83 [2] a8 b6 [2] 86 b6 [2] b9 aa }

  condition:
    any of them
}