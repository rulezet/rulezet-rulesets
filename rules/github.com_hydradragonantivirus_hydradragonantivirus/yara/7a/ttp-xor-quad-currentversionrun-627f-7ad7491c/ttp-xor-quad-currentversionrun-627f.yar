rule TTP_XOR_QUAD_CurrentVersionRun_627f {
  strings:
    $key_627f = { 31 10 [2] 15 1e [2] 3e 32 [2] 10 10 [2] 04 0b [2] 0b 11 [2] 15 0c [2] 17 0d [2] 0c 0b [2] 10 0c [2] 0c 23 }

  condition:
    any of them
}