rule TTP_XOR_WriteProcessMemory_1bf4 {
  strings:
    $key_1bf4 = { 4c 86 [2] 7e a4 [2] 78 91 [2] 56 91 [2] 69 8d }

  condition:
    any of them
}