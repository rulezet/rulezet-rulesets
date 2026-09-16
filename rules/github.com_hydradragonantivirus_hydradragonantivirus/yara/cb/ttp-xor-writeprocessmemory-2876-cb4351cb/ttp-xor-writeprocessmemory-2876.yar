rule TTP_XOR_WriteProcessMemory_2876 {
  strings:
    $key_2876 = { 7f 04 [2] 4d 26 [2] 4b 13 [2] 65 13 [2] 5a 0f }

  condition:
    any of them
}