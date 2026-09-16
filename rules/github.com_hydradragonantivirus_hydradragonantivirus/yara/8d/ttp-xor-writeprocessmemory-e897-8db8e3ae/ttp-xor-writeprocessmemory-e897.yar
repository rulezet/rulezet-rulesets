rule TTP_XOR_WriteProcessMemory_e897 {
  strings:
    $key_e897 = { bf e5 [2] 8d c7 [2] 8b f2 [2] a5 f2 [2] 9a ee }

  condition:
    any of them
}