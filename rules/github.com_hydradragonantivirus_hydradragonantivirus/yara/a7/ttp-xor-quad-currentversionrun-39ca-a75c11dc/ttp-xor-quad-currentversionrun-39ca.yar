rule TTP_XOR_QUAD_CurrentVersionRun_39ca {
  strings:
    $key_39ca = { 6a a5 [2] 4e ab [2] 65 87 [2] 4b a5 [2] 5f be [2] 50 a4 [2] 4e b9 [2] 4c b8 [2] 57 be [2] 4b b9 [2] 57 96 }

  condition:
    any of them
}