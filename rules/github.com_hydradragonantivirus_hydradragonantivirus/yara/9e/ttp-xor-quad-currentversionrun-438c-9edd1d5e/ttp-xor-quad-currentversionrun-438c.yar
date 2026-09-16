rule TTP_XOR_QUAD_CurrentVersionRun_438c {
  strings:
    $key_438c = { 10 e3 [2] 34 ed [2] 1f c1 [2] 31 e3 [2] 25 f8 [2] 2a e2 [2] 34 ff [2] 36 fe [2] 2d f8 [2] 31 ff [2] 2d d0 }

  condition:
    any of them
}