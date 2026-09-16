rule TTP_XOR_QUAD_CurrentVersionRun_3533 {
  strings:
    $key_3533 = { 66 5c [2] 42 52 [2] 69 7e [2] 47 5c [2] 53 47 [2] 5c 5d [2] 42 40 [2] 40 41 [2] 5b 47 [2] 47 40 [2] 5b 6f }

  condition:
    any of them
}