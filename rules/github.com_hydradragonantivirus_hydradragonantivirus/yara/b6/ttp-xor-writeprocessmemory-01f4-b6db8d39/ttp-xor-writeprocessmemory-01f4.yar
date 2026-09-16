rule TTP_XOR_WriteProcessMemory_01f4 {
  strings:
    $key_01f4 = { 56 86 [2] 64 a4 [2] 62 91 [2] 4c 91 [2] 73 8d }

  condition:
    any of them
}