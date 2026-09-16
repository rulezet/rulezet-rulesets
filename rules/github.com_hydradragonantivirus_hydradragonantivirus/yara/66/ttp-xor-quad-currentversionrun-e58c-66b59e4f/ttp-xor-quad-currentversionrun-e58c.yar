rule TTP_XOR_QUAD_CurrentVersionRun_e58c {
  strings:
    $key_e58c = { b6 e3 [2] 92 ed [2] b9 c1 [2] 97 e3 [2] 83 f8 [2] 8c e2 [2] 92 ff [2] 90 fe [2] 8b f8 [2] 97 ff [2] 8b d0 }

  condition:
    any of them
}