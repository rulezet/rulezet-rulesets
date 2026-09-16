rule TTP_XOR_QUAD_CurrentVersionRun_308c {
  strings:
    $key_308c = { 63 e3 [2] 47 ed [2] 6c c1 [2] 42 e3 [2] 56 f8 [2] 59 e2 [2] 47 ff [2] 45 fe [2] 5e f8 [2] 42 ff [2] 5e d0 }

  condition:
    any of them
}