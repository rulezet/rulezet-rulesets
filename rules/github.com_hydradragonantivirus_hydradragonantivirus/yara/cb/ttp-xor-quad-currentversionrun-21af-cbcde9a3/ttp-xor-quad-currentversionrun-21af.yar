rule TTP_XOR_QUAD_CurrentVersionRun_21af {
  strings:
    $key_21af = { 72 c0 [2] 56 ce [2] 7d e2 [2] 53 c0 [2] 47 db [2] 48 c1 [2] 56 dc [2] 54 dd [2] 4f db [2] 53 dc [2] 4f f3 }

  condition:
    any of them
}