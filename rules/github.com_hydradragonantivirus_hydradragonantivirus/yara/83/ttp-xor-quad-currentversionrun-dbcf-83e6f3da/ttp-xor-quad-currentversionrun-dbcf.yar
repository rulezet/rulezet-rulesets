rule TTP_XOR_QUAD_CurrentVersionRun_dbcf {
  strings:
    $key_dbcf = { 88 a0 [2] ac ae [2] 87 82 [2] a9 a0 [2] bd bb [2] b2 a1 [2] ac bc [2] ae bd [2] b5 bb [2] a9 bc [2] b5 93 }

  condition:
    any of them
}