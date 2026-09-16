rule TTP_XOR_QUAD_CurrentVersionRun_758c {
  strings:
    $key_758c = { 26 e3 [2] 02 ed [2] 29 c1 [2] 07 e3 [2] 13 f8 [2] 1c e2 [2] 02 ff [2] 00 fe [2] 1b f8 [2] 07 ff [2] 1b d0 }

  condition:
    any of them
}