rule TTP_XOR_QUAD_CurrentVersionRun_354f {
  strings:
    $key_354f = { 66 20 [2] 42 2e [2] 69 02 [2] 47 20 [2] 53 3b [2] 5c 21 [2] 42 3c [2] 40 3d [2] 5b 3b [2] 47 3c [2] 5b 13 }

  condition:
    any of them
}