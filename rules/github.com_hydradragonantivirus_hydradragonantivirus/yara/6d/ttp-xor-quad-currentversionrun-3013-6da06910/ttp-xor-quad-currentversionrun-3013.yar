rule TTP_XOR_QUAD_CurrentVersionRun_3013 {
  strings:
    $key_3013 = { 63 7c [2] 47 72 [2] 6c 5e [2] 42 7c [2] 56 67 [2] 59 7d [2] 47 60 [2] 45 61 [2] 5e 67 [2] 42 60 [2] 5e 4f }

  condition:
    any of them
}