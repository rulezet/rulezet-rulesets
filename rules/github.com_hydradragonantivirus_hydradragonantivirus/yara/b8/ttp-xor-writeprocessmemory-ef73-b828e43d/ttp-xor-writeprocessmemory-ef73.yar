rule TTP_XOR_WriteProcessMemory_ef73 {
  strings:
    $key_ef73 = { b8 01 [2] 8a 23 [2] 8c 16 [2] a2 16 [2] 9d 0a }

  condition:
    any of them
}