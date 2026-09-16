rule TTP_XOR_QUAD_CurrentVersionRun_d70f {
  strings:
    $key_d70f = { 84 60 [2] a0 6e [2] 8b 42 [2] a5 60 [2] b1 7b [2] be 61 [2] a0 7c [2] a2 7d [2] b9 7b [2] a5 7c [2] b9 53 }

  condition:
    any of them
}