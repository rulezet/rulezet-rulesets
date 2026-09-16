rule TTP_XOR_WriteProcessMemory_ef04 {
  strings:
    $key_ef04 = { b8 76 [2] 8a 54 [2] 8c 61 [2] a2 61 [2] 9d 7d }

  condition:
    any of them
}