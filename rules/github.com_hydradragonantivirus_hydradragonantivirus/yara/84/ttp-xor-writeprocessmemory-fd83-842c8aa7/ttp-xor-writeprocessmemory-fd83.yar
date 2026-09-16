rule TTP_XOR_WriteProcessMemory_fd83 {
  strings:
    $key_fd83 = { aa f1 [2] 98 d3 [2] 9e e6 [2] b0 e6 [2] 8f fa }

  condition:
    any of them
}