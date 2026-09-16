rule TTP_XOR_QUAD_CurrentVersionRun_068c {
  strings:
    $key_068c = { 55 e3 [2] 71 ed [2] 5a c1 [2] 74 e3 [2] 60 f8 [2] 6f e2 [2] 71 ff [2] 73 fe [2] 68 f8 [2] 74 ff [2] 68 d0 }

  condition:
    any of them
}