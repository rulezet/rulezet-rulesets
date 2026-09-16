rule TTP_XOR_WriteProcessMemory_0e94 {
  strings:
    $key_0e94 = { 59 e6 [2] 6b c4 [2] 6d f1 [2] 43 f1 [2] 7c ed }

  condition:
    any of them
}