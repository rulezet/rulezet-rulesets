rule TTP_XOR_WriteProcessMemory_3183 {
  strings:
    $key_3183 = { 66 f1 [2] 54 d3 [2] 52 e6 [2] 7c e6 [2] 43 fa }

  condition:
    any of them
}