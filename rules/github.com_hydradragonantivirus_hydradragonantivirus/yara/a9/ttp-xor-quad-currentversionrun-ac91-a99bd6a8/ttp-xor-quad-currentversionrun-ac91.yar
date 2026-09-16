rule TTP_XOR_QUAD_CurrentVersionRun_ac91 {
  strings:
    $key_ac91 = { ff fe [2] db f0 [2] f0 dc [2] de fe [2] ca e5 [2] c5 ff [2] db e2 [2] d9 e3 [2] c2 e5 [2] de e2 [2] c2 cd }

  condition:
    any of them
}