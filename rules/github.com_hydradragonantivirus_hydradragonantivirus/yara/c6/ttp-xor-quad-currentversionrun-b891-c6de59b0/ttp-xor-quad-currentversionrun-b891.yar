rule TTP_XOR_QUAD_CurrentVersionRun_b891 {
  strings:
    $key_b891 = { eb fe [2] cf f0 [2] e4 dc [2] ca fe [2] de e5 [2] d1 ff [2] cf e2 [2] cd e3 [2] d6 e5 [2] ca e2 [2] d6 cd }

  condition:
    any of them
}