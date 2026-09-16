rule TTP_XOR_WriteProcessMemory_f934 {
  strings:
    $key_f934 = { ae 46 [2] 9c 64 [2] 9a 51 [2] b4 51 [2] 8b 4d }

  condition:
    any of them
}