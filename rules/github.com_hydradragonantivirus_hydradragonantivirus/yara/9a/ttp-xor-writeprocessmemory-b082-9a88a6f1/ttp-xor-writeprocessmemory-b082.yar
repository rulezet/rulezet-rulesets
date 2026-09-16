rule TTP_XOR_WriteProcessMemory_b082 {
  strings:
    $key_b082 = { e7 f0 [2] d5 d2 [2] d3 e7 [2] fd e7 [2] c2 fb }

  condition:
    any of them
}