rule TTP_XOR_QUAD_CurrentVersionRun_b0db {
  strings:
    $key_b0db = { e3 b4 [2] c7 ba [2] ec 96 [2] c2 b4 [2] d6 af [2] d9 b5 [2] c7 a8 [2] c5 a9 [2] de af [2] c2 a8 [2] de 87 }

  condition:
    any of them
}