rule TTP_XOR_WriteProcessMemory_c913 {
  strings:
    $key_c913 = { 9e 61 [2] ac 43 [2] aa 76 [2] 84 76 [2] bb 6a }

  condition:
    any of them
}