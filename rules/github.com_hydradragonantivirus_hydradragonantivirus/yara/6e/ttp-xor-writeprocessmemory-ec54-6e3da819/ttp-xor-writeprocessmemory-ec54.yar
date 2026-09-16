rule TTP_XOR_WriteProcessMemory_ec54 {
  strings:
    $key_ec54 = { bb 26 [2] 89 04 [2] 8f 31 [2] a1 31 [2] 9e 2d }

  condition:
    any of them
}