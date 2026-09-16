rule TTP_XOR_WriteProcessMemory_1301 {
  strings:
    $key_1301 = { 44 73 [2] 76 51 [2] 70 64 [2] 5e 64 [2] 61 78 }

  condition:
    any of them
}