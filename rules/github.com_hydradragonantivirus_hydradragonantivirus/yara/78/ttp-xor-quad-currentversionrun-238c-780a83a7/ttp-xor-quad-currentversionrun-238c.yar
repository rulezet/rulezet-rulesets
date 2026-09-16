rule TTP_XOR_QUAD_CurrentVersionRun_238c {
  strings:
    $key_238c = { 70 e3 [2] 54 ed [2] 7f c1 [2] 51 e3 [2] 45 f8 [2] 4a e2 [2] 54 ff [2] 56 fe [2] 4d f8 [2] 51 ff [2] 4d d0 }

  condition:
    any of them
}