rule TTP_XOR_WriteProcessMemory_7c83 {
  strings:
    $key_7c83 = { 2b f1 [2] 19 d3 [2] 1f e6 [2] 31 e6 [2] 0e fa }

  condition:
    any of them
}