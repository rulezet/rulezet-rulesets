rule TTP_XOR_WriteProcessMemory_f326 {
  strings:
    $key_f326 = { a4 54 [2] 96 76 [2] 90 43 [2] be 43 [2] 81 5f }

  condition:
    any of them
}