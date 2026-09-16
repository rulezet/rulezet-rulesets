rule TTP_XOR_WriteProcessMemory_9e94 {
  strings:
    $key_9e94 = { c9 e6 [2] fb c4 [2] fd f1 [2] d3 f1 [2] ec ed }

  condition:
    any of them
}