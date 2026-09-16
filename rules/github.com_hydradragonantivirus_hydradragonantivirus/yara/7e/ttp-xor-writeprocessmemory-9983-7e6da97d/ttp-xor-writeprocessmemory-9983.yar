rule TTP_XOR_WriteProcessMemory_9983 {
  strings:
    $key_9983 = { ce f1 [2] fc d3 [2] fa e6 [2] d4 e6 [2] eb fa }

  condition:
    any of them
}