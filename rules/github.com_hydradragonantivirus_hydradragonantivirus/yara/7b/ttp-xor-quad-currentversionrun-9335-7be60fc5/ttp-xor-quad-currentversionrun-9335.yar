rule TTP_XOR_QUAD_CurrentVersionRun_9335 {
  strings:
    $key_9335 = { c0 5a [2] e4 54 [2] cf 78 [2] e1 5a [2] f5 41 [2] fa 5b [2] e4 46 [2] e6 47 [2] fd 41 [2] e1 46 [2] fd 69 }

  condition:
    any of them
}