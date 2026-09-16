rule TTP_XOR_QUAD_CurrentVersionRun_28cd {
  strings:
    $key_28cd = { 7b a2 [2] 5f ac [2] 74 80 [2] 5a a2 [2] 4e b9 [2] 41 a3 [2] 5f be [2] 5d bf [2] 46 b9 [2] 5a be [2] 46 91 }

  condition:
    any of them
}