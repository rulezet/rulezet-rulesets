rule TTP_XOR_QUAD_CurrentVersionRun_a08c {
  strings:
    $key_a08c = { f3 e3 [2] d7 ed [2] fc c1 [2] d2 e3 [2] c6 f8 [2] c9 e2 [2] d7 ff [2] d5 fe [2] ce f8 [2] d2 ff [2] ce d0 }

  condition:
    any of them
}