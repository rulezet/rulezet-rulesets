rule TTP_XOR_QUAD_CurrentVersionRun_3733 {
  strings:
    $key_3733 = { 64 5c [2] 40 52 [2] 6b 7e [2] 45 5c [2] 51 47 [2] 5e 5d [2] 40 40 [2] 42 41 [2] 59 47 [2] 45 40 [2] 59 6f }

  condition:
    any of them
}