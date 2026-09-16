rule TTP_XOR_QUAD_CurrentVersionRun_e8cd {
  strings:
    $key_e8cd = { bb a2 [2] 9f ac [2] b4 80 [2] 9a a2 [2] 8e b9 [2] 81 a3 [2] 9f be [2] 9d bf [2] 86 b9 [2] 9a be [2] 86 91 }

  condition:
    any of them
}