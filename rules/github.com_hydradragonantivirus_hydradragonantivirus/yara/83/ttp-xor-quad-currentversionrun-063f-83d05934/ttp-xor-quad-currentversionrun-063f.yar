rule TTP_XOR_QUAD_CurrentVersionRun_063f {
  strings:
    $key_063f = { 55 50 [2] 71 5e [2] 5a 72 [2] 74 50 [2] 60 4b [2] 6f 51 [2] 71 4c [2] 73 4d [2] 68 4b [2] 74 4c [2] 68 63 }

  condition:
    any of them
}