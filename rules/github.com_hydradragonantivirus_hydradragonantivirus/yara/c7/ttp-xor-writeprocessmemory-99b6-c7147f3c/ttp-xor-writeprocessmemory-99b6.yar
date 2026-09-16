rule TTP_XOR_WriteProcessMemory_99b6 {
  strings:
    $key_99b6 = { ce c4 [2] fc e6 [2] fa d3 [2] d4 d3 [2] eb cf }

  condition:
    any of them
}