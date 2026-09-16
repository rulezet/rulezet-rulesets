rule TTP_XOR_WriteProcessMemory_08c6 {
  strings:
    $key_08c6 = { 5f b4 [2] 6d 96 [2] 6b a3 [2] 45 a3 [2] 7a bf }

  condition:
    any of them
}