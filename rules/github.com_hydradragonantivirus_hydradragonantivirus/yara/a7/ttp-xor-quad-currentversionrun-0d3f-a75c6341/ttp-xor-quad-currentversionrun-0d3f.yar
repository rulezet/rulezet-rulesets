rule TTP_XOR_QUAD_CurrentVersionRun_0d3f {
  strings:
    $key_0d3f = { 5e 50 [2] 7a 5e [2] 51 72 [2] 7f 50 [2] 6b 4b [2] 64 51 [2] 7a 4c [2] 78 4d [2] 63 4b [2] 7f 4c [2] 63 63 }

  condition:
    any of them
}