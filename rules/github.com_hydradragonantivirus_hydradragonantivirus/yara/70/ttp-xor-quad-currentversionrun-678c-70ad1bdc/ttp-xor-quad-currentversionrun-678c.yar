rule TTP_XOR_QUAD_CurrentVersionRun_678c {
  strings:
    $key_678c = { 34 e3 [2] 10 ed [2] 3b c1 [2] 15 e3 [2] 01 f8 [2] 0e e2 [2] 10 ff [2] 12 fe [2] 09 f8 [2] 15 ff [2] 09 d0 }

  condition:
    any of them
}