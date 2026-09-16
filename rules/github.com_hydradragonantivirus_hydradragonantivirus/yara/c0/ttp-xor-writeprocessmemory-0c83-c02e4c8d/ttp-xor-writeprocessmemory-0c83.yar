rule TTP_XOR_WriteProcessMemory_0c83 {
  strings:
    $key_0c83 = { 5b f1 [2] 69 d3 [2] 6f e6 [2] 41 e6 [2] 7e fa }

  condition:
    any of them
}