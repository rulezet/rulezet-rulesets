rule TTP_XOR_QUAD_CurrentVersionRun_8d91 {
  strings:
    $key_8d91 = { de fe [2] fa f0 [2] d1 dc [2] ff fe [2] eb e5 [2] e4 ff [2] fa e2 [2] f8 e3 [2] e3 e5 [2] ff e2 [2] e3 cd }

  condition:
    any of them
}