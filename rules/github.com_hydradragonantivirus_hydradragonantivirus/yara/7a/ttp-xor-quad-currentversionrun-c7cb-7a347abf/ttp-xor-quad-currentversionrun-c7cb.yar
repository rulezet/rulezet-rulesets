rule TTP_XOR_QUAD_CurrentVersionRun_c7cb {
  strings:
    $key_c7cb = { 94 a4 [2] b0 aa [2] 9b 86 [2] b5 a4 [2] a1 bf [2] ae a5 [2] b0 b8 [2] b2 b9 [2] a9 bf [2] b5 b8 [2] a9 97 }

  condition:
    any of them
}