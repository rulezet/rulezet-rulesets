rule TTP_XOR_QUAD_CurrentVersionRun_7d3f {
  strings:
    $key_7d3f = { 2e 50 [2] 0a 5e [2] 21 72 [2] 0f 50 [2] 1b 4b [2] 14 51 [2] 0a 4c [2] 08 4d [2] 13 4b [2] 0f 4c [2] 13 63 }

  condition:
    any of them
}