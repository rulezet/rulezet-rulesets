rule TTP_XOR_QUAD_CurrentVersionRun_ee8d {
  strings:
    $key_ee8d = { bd e2 [2] 99 ec [2] b2 c0 [2] 9c e2 [2] 88 f9 [2] 87 e3 [2] 99 fe [2] 9b ff [2] 80 f9 [2] 9c fe [2] 80 d1 }

  condition:
    any of them
}