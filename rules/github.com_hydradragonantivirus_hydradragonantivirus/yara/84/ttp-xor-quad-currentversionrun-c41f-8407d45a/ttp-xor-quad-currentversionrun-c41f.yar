rule TTP_XOR_QUAD_CurrentVersionRun_c41f {
  strings:
    $key_c41f = { 97 70 [2] b3 7e [2] 98 52 [2] b6 70 [2] a2 6b [2] ad 71 [2] b3 6c [2] b1 6d [2] aa 6b [2] b6 6c [2] aa 43 }

  condition:
    any of them
}