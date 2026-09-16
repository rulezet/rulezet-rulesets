rule TTP_XOR_WriteProcessMemory_3213 {
  strings:
    $key_3213 = { 65 61 [2] 57 43 [2] 51 76 [2] 7f 76 [2] 40 6a }

  condition:
    any of them
}