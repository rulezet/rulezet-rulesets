rule TTP_XOR_QUAD_CurrentVersionRun_8f15 {
  strings:
    $key_8f15 = { dc 7a [2] f8 74 [2] d3 58 [2] fd 7a [2] e9 61 [2] e6 7b [2] f8 66 [2] fa 67 [2] e1 61 [2] fd 66 [2] e1 49 }

  condition:
    any of them
}