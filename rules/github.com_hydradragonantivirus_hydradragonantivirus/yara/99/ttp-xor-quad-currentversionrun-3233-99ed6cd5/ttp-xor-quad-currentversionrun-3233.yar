rule TTP_XOR_QUAD_CurrentVersionRun_3233 {
  strings:
    $key_3233 = { 61 5c [2] 45 52 [2] 6e 7e [2] 40 5c [2] 54 47 [2] 5b 5d [2] 45 40 [2] 47 41 [2] 5c 47 [2] 40 40 [2] 5c 6f }

  condition:
    any of them
}