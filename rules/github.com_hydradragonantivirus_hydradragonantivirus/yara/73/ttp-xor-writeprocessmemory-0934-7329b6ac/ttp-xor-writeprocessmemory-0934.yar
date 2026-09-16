rule TTP_XOR_WriteProcessMemory_0934 {
  strings:
    $key_0934 = { 5e 46 [2] 6c 64 [2] 6a 51 [2] 44 51 [2] 7b 4d }

  condition:
    any of them
}