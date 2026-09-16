rule TTP_XOR_QUAD_CurrentVersionRun_563f {
  strings:
    $key_563f = { 05 50 [2] 21 5e [2] 0a 72 [2] 24 50 [2] 30 4b [2] 3f 51 [2] 21 4c [2] 23 4d [2] 38 4b [2] 24 4c [2] 38 63 }

  condition:
    any of them
}