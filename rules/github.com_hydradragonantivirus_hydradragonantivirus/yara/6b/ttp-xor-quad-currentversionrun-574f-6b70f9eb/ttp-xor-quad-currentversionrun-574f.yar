rule TTP_XOR_QUAD_CurrentVersionRun_574f {
  strings:
    $key_574f = { 04 20 [2] 20 2e [2] 0b 02 [2] 25 20 [2] 31 3b [2] 3e 21 [2] 20 3c [2] 22 3d [2] 39 3b [2] 25 3c [2] 39 13 }

  condition:
    any of them
}