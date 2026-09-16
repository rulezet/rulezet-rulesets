rule TTP_XOR_WriteProcessMemory_e8c6 {
  strings:
    $key_e8c6 = { bf b4 [2] 8d 96 [2] 8b a3 [2] a5 a3 [2] 9a bf }

  condition:
    any of them
}