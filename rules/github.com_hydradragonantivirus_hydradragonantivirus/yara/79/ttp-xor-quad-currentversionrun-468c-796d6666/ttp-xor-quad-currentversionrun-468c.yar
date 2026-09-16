rule TTP_XOR_QUAD_CurrentVersionRun_468c {
  strings:
    $key_468c = { 15 e3 [2] 31 ed [2] 1a c1 [2] 34 e3 [2] 20 f8 [2] 2f e2 [2] 31 ff [2] 33 fe [2] 28 f8 [2] 34 ff [2] 28 d0 }

  condition:
    any of them
}