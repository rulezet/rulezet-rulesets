rule TTP_XOR_QUAD_CurrentVersionRun_18cd {
  strings:
    $key_18cd = { 4b a2 [2] 6f ac [2] 44 80 [2] 6a a2 [2] 7e b9 [2] 71 a3 [2] 6f be [2] 6d bf [2] 76 b9 [2] 6a be [2] 76 91 }

  condition:
    any of them
}