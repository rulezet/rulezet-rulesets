rule TTP_XOR_QUAD_CurrentVersionRun_6d3f {
  strings:
    $key_6d3f = { 3e 50 [2] 1a 5e [2] 31 72 [2] 1f 50 [2] 0b 4b [2] 04 51 [2] 1a 4c [2] 18 4d [2] 03 4b [2] 1f 4c [2] 03 63 }

  condition:
    any of them
}