rule TTP_XOR_WriteProcessMemory_1c83 {
  strings:
    $key_1c83 = { 4b f1 [2] 79 d3 [2] 7f e6 [2] 51 e6 [2] 6e fa }

  condition:
    any of them
}