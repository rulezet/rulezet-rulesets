rule TTP_XOR_QUAD_CurrentVersionRun_68cd {
  strings:
    $key_68cd = { 3b a2 [2] 1f ac [2] 34 80 [2] 1a a2 [2] 0e b9 [2] 01 a3 [2] 1f be [2] 1d bf [2] 06 b9 [2] 1a be [2] 06 91 }

  condition:
    any of them
}