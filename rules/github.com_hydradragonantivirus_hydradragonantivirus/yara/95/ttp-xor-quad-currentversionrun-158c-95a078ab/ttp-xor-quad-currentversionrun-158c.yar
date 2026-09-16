rule TTP_XOR_QUAD_CurrentVersionRun_158c {
  strings:
    $key_158c = { 46 e3 [2] 62 ed [2] 49 c1 [2] 67 e3 [2] 73 f8 [2] 7c e2 [2] 62 ff [2] 60 fe [2] 7b f8 [2] 67 ff [2] 7b d0 }

  condition:
    any of them
}