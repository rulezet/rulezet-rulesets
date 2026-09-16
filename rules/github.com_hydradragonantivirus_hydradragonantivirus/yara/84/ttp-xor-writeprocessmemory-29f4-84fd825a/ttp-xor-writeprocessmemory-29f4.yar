rule TTP_XOR_WriteProcessMemory_29f4 {
  strings:
    $key_29f4 = { 7e 86 [2] 4c a4 [2] 4a 91 [2] 64 91 [2] 5b 8d }

  condition:
    any of them
}