rule TTP_XOR_WriteProcessMemory_ef53 {
  strings:
    $key_ef53 = { b8 21 [2] 8a 03 [2] 8c 36 [2] a2 36 [2] 9d 2a }

  condition:
    any of them
}