rule TTP_XOR_WriteProcessMemory_e894 {
  strings:
    $key_e894 = { bf e6 [2] 8d c4 [2] 8b f1 [2] a5 f1 [2] 9a ed }

  condition:
    any of them
}