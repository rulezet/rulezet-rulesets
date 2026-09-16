rule TTP_XOR_QUAD_CurrentVersionRun_32dd {
  strings:
    $key_32dd = { 61 b2 [2] 45 bc [2] 6e 90 [2] 40 b2 [2] 54 a9 [2] 5b b3 [2] 45 ae [2] 47 af [2] 5c a9 [2] 40 ae [2] 5c 81 }

  condition:
    any of them
}