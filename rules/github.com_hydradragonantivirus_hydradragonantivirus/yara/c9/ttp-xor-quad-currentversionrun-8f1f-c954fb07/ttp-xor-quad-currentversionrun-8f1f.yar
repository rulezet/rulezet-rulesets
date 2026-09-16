rule TTP_XOR_QUAD_CurrentVersionRun_8f1f {
  strings:
    $key_8f1f = { dc 70 [2] f8 7e [2] d3 52 [2] fd 70 [2] e9 6b [2] e6 71 [2] f8 6c [2] fa 6d [2] e1 6b [2] fd 6c [2] e1 43 }

  condition:
    any of them
}