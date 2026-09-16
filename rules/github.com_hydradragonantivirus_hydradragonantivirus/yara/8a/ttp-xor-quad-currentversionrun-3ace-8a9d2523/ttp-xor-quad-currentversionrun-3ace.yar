rule TTP_XOR_QUAD_CurrentVersionRun_3ace {
  strings:
    $key_3ace = { 69 a1 [2] 4d af [2] 66 83 [2] 48 a1 [2] 5c ba [2] 53 a0 [2] 4d bd [2] 4f bc [2] 54 ba [2] 48 bd [2] 54 92 }

  condition:
    any of them
}