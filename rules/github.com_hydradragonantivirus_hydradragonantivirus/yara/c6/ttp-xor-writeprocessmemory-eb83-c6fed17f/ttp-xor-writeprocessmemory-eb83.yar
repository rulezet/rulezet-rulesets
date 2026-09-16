rule TTP_XOR_WriteProcessMemory_eb83 {
  strings:
    $key_eb83 = { bc f1 [2] 8e d3 [2] 88 e6 [2] a6 e6 [2] 99 fa }

  condition:
    any of them
}