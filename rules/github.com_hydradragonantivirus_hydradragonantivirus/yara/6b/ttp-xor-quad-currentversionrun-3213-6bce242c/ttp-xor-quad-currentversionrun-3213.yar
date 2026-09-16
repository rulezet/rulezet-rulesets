rule TTP_XOR_QUAD_CurrentVersionRun_3213 {
  strings:
    $key_3213 = { 61 7c [2] 45 72 [2] 6e 5e [2] 40 7c [2] 54 67 [2] 5b 7d [2] 45 60 [2] 47 61 [2] 5c 67 [2] 40 60 [2] 5c 4f }

  condition:
    any of them
}