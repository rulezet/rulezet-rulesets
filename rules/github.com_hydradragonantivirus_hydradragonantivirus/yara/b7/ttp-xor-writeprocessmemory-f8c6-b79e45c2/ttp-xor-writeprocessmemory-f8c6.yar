rule TTP_XOR_WriteProcessMemory_f8c6 {
  strings:
    $key_f8c6 = { af b4 [2] 9d 96 [2] 9b a3 [2] b5 a3 [2] 8a bf }

  condition:
    any of them
}