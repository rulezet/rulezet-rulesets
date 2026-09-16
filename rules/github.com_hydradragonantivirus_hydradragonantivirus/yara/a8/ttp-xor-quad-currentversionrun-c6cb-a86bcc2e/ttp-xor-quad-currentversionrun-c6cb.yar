rule TTP_XOR_QUAD_CurrentVersionRun_c6cb {
  strings:
    $key_c6cb = { 95 a4 [2] b1 aa [2] 9a 86 [2] b4 a4 [2] a0 bf [2] af a5 [2] b1 b8 [2] b3 b9 [2] a8 bf [2] b4 b8 [2] a8 97 }

  condition:
    any of them
}