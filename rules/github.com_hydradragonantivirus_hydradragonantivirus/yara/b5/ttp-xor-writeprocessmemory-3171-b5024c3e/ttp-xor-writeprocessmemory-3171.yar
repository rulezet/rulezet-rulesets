rule TTP_XOR_WriteProcessMemory_3171 {
  strings:
    $key_3171 = { 66 03 [2] 54 21 [2] 52 14 [2] 7c 14 [2] 43 08 }

  condition:
    any of them
}