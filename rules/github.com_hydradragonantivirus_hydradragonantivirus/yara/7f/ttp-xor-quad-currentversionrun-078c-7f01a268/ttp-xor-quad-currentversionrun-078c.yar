rule TTP_XOR_QUAD_CurrentVersionRun_078c {
  strings:
    $key_078c = { 54 e3 [2] 70 ed [2] 5b c1 [2] 75 e3 [2] 61 f8 [2] 6e e2 [2] 70 ff [2] 72 fe [2] 69 f8 [2] 75 ff [2] 69 d0 }

  condition:
    any of them
}