rule TTP_XOR_WriteProcessMemory_3601 {
  strings:
    $key_3601 = { 61 73 [2] 53 51 [2] 55 64 [2] 7b 64 [2] 44 78 }

  condition:
    any of them
}