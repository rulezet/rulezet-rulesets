rule TTP_XOR_QUAD_CurrentVersionRun_d091 {
  strings:
    $key_d091 = { 83 fe [2] a7 f0 [2] 8c dc [2] a2 fe [2] b6 e5 [2] b9 ff [2] a7 e2 [2] a5 e3 [2] be e5 [2] a2 e2 [2] be cd }

  condition:
    any of them
}