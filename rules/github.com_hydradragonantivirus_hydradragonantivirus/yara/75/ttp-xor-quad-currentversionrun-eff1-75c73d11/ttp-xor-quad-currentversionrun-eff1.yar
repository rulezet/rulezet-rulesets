rule TTP_XOR_QUAD_CurrentVersionRun_eff1 {
  strings:
    $key_eff1 = { bc 9e [2] 98 90 [2] b3 bc [2] 9d 9e [2] 89 85 [2] 86 9f [2] 98 82 [2] 9a 83 [2] 81 85 [2] 9d 82 [2] 81 ad }

  condition:
    any of them
}