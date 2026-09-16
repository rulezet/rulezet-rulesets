rule TTP_XOR_QUAD_CurrentVersionRun_c47f {
  strings:
    $key_c47f = { 97 10 [2] b3 1e [2] 98 32 [2] b6 10 [2] a2 0b [2] ad 11 [2] b3 0c [2] b1 0d [2] aa 0b [2] b6 0c [2] aa 23 }

  condition:
    any of them
}