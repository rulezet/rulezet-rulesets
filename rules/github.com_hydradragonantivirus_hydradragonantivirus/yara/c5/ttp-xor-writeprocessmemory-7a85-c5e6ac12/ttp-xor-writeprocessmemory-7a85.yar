rule TTP_XOR_WriteProcessMemory_7a85 {
  strings:
    $key_7a85 = { 2d f7 [2] 1f d5 [2] 19 e0 [2] 37 e0 [2] 08 fc }

  condition:
    any of them
}