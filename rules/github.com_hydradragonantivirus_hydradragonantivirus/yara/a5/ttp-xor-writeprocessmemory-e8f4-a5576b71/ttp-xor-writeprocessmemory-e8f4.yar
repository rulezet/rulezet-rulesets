rule TTP_XOR_WriteProcessMemory_e8f4 {
  strings:
    $key_e8f4 = { bf 86 [2] 8d a4 [2] 8b 91 [2] a5 91 [2] 9a 8d }

  condition:
    any of them
}