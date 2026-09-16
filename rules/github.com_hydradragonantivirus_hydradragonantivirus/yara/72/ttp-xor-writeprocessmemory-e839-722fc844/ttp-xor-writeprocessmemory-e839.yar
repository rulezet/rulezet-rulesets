rule TTP_XOR_WriteProcessMemory_e839 {
  strings:
    $key_e839 = { bf 4b [2] 8d 69 [2] 8b 5c [2] a5 5c [2] 9a 40 }

  condition:
    any of them
}