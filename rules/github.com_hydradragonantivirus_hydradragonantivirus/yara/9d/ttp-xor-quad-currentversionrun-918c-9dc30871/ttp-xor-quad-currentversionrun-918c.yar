rule TTP_XOR_QUAD_CurrentVersionRun_918c {
  strings:
    $key_918c = { c2 e3 [2] e6 ed [2] cd c1 [2] e3 e3 [2] f7 f8 [2] f8 e2 [2] e6 ff [2] e4 fe [2] ff f8 [2] e3 ff [2] ff d0 }

  condition:
    any of them
}