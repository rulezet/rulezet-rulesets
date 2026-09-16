rule TTP_XOR_QUAD_CurrentVersionRun_038c {
  strings:
    $key_038c = { 50 e3 [2] 74 ed [2] 5f c1 [2] 71 e3 [2] 65 f8 [2] 6a e2 [2] 74 ff [2] 76 fe [2] 6d f8 [2] 71 ff [2] 6d d0 }

  condition:
    any of them
}