rule TTP_XOR_WriteProcessMemory_e801 {
  strings:
    $key_e801 = { bf 73 [2] 8d 51 [2] 8b 64 [2] a5 64 [2] 9a 78 }

  condition:
    any of them
}