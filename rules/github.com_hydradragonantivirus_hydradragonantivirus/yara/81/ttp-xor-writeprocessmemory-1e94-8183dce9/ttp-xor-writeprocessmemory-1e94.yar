rule TTP_XOR_WriteProcessMemory_1e94 {
  strings:
    $key_1e94 = { 49 e6 [2] 7b c4 [2] 7d f1 [2] 53 f1 [2] 6c ed }

  condition:
    any of them
}