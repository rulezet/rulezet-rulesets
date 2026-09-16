rule TTP_XOR_QUAD_CurrentVersionRun_b712 {
  strings:
    $key_b712 = { e4 7d [2] c0 73 [2] eb 5f [2] c5 7d [2] d1 66 [2] de 7c [2] c0 61 [2] c2 60 [2] d9 66 [2] c5 61 [2] d9 4e }

  condition:
    any of them
}