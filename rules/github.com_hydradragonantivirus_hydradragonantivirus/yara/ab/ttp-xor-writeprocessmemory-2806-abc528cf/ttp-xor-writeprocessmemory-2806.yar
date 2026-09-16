rule TTP_XOR_WriteProcessMemory_2806 {
  strings:
    $key_2806 = { 7f 74 [2] 4d 56 [2] 4b 63 [2] 65 63 [2] 5a 7f }

  condition:
    any of them
}